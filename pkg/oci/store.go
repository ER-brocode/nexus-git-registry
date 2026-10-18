package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrBlobNotFound = errors.New("blob not found")
	ErrUploadActive = errors.New("upload session already active")
)

// BlobStore manages content-addressable storage of layer blobs and config blobs.
type BlobStore struct {
	mu        sync.RWMutex
	baseDir   string
	uploads   map[string]*UploadSession
	uploadMu  sync.Mutex
	cdcChunker *FastCDC
}

// UploadSession tracks an in-progress resumable chunked upload.
type UploadSession struct {
	ID        string
	Repo      string
	CreatedAt time.Time
	TempFile  *os.File
	Size      int64
	hasher    io.Writer
	shaState  interface{ Sum([]byte) []byte }
}

// NewBlobStore initializes a Content-Addressable Blob Store rooted at baseDir.
func NewBlobStore(baseDir string) (*BlobStore, error) {
	blobsDir := filepath.Join(baseDir, "blobs", "sha256")
	uploadsDir := filepath.Join(baseDir, "uploads")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create blobs dir: %w", err)
	}
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create uploads dir: %w", err)
	}

	return &BlobStore{
		baseDir:    baseDir,
		uploads:    make(map[string]*UploadSession),
		cdcChunker: NewFastCDC(16*1024, 64*1024, 256*1024), // 16KB min, 64KB avg, 256KB max
	}, nil
}

// blobPath computes the storage path for a given sha256 digest: blobs/sha256/ab/abcdef...
func (s *BlobStore) blobPath(digest string) (string, error) {
	if err := ValidateDigest(digest); err != nil {
		return "", err
	}
	parts := stringsSplit2(digest, ":")
	hash := parts[1]
	prefix := hash[:2]
	return filepath.Join(s.baseDir, "blobs", parts[0], prefix, hash), nil
}

// stringsSplit2 splits string by sep into 2 parts.
func stringsSplit2(s, sep string) []string {
	idx := -1
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			idx = i
			break
		}
	}
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

// Exists checks if a blob with the specified digest exists in the store.
func (s *BlobStore) Exists(digest string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, err := s.blobPath(digest)
	if err != nil {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Stat returns the size in bytes of an existing blob.
func (s *BlobStore) Stat(digest string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, err := s.blobPath(digest)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrBlobNotFound
		}
		return 0, err
	}
	return info.Size(), nil
}

// Open retrieves a read stream for the specified digest.
func (s *BlobStore) Open(digest string) (io.ReadCloser, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, err := s.blobPath(digest)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrBlobNotFound
		}
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// Put saves data directly into the store under the expected digest, verifying checksum.
func (s *BlobStore) Put(expectedDigest string, r io.Reader) (string, int64, error) {
	targetPath, err := s.blobPath(expectedDigest)
	if err != nil {
		return "", 0, err
	}

	if s.Exists(expectedDigest) {
		size, _ := s.Stat(expectedDigest)
		// Drain reader
		io.Copy(io.Discard, r)
		return expectedDigest, size, nil
	}

	tempDir := filepath.Join(s.baseDir, "uploads")
	tempFile, err := os.CreateTemp(tempDir, "blob-*")
	if err != nil {
		return "", 0, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)

	hasher := sha256.New()
	multiWriter := io.MultiWriter(tempFile, hasher)

	written, err := io.Copy(multiWriter, r)
	tempFile.Close()
	if err != nil {
		return "", 0, fmt.Errorf("failed to write blob: %w", err)
	}

	computedDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if expectedDigest != "" && computedDigest != expectedDigest {
		return "", 0, fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expectedDigest, computedDigest)
	}

	if targetPath == "" {
		targetPath, _ = s.blobPath(computedDigest)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return "", 0, fmt.Errorf("failed to make target directory: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Atomic rename or move
	if err := os.Rename(tempName, targetPath); err != nil {
		// Fallback for cross-device or Windows rename conflicts
		if copyErr := copyFile(tempName, targetPath); copyErr != nil {
			return "", 0, fmt.Errorf("failed to finalize blob file: %w", copyErr)
		}
	}

	return computedDigest, written, nil
}

// StartUpload initializes a new chunked upload session.
func (s *BlobStore) StartUpload(repo, sessionID string) (*UploadSession, error) {
	s.uploadMu.Lock()
	defer s.uploadMu.Unlock()

	tempDir := filepath.Join(s.baseDir, "uploads")
	tempFile, err := os.CreateTemp(tempDir, fmt.Sprintf("upload-%s-*", sessionID))
	if err != nil {
		return nil, fmt.Errorf("failed to start upload session: %w", err)
	}

	session := &UploadSession{
		ID:        sessionID,
		Repo:      repo,
		CreatedAt: time.Now(),
		TempFile:  tempFile,
		Size:      0,
	}
	s.uploads[sessionID] = session
	return session, nil
}

// WriteChunk appends data bytes to an ongoing upload session.
func (s *BlobStore) WriteChunk(sessionID string, r io.Reader) (int64, error) {
	s.uploadMu.Lock()
	session, ok := s.uploads[sessionID]
	s.uploadMu.Unlock()

	if !ok {
		return 0, fmt.Errorf("upload session %s not found", sessionID)
	}

	written, err := io.Copy(session.TempFile, r)
	if err != nil {
		return 0, err
	}
	session.Size += written
	return session.Size, nil
}

// FinishUpload commits the uploaded chunks and moves into content-addressable storage.
func (s *BlobStore) FinishUpload(sessionID, expectedDigest string) (string, int64, error) {
	s.uploadMu.Lock()
	session, ok := s.uploads[sessionID]
	if ok {
		delete(s.uploads, sessionID)
	}
	s.uploadMu.Unlock()

	if !ok {
		return "", 0, fmt.Errorf("upload session %s not found", sessionID)
	}

	session.TempFile.Close()
	defer os.Remove(session.TempFile.Name())

	// Read and verify digest
	f, err := os.Open(session.TempFile.Name())
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	hasher := sha256.New()
	written, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}

	computed := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if expectedDigest != "" && computed != expectedDigest {
		return "", 0, fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expectedDigest, computed)
	}

	targetPath, err := s.blobPath(computed)
	if err != nil {
		return "", 0, err
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return "", 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Rename(session.TempFile.Name(), targetPath); err != nil {
		if err := copyFile(session.TempFile.Name(), targetPath); err != nil {
			return "", 0, fmt.Errorf("failed to commit blob: %w", err)
		}
	}

	return computed, written, nil
}

// CancelUpload aborts an active session and removes temporary files.
func (s *BlobStore) CancelUpload(sessionID string) error {
	s.uploadMu.Lock()
	session, ok := s.uploads[sessionID]
	if ok {
		delete(s.uploads, sessionID)
	}
	s.uploadMu.Unlock()

	if !ok {
		return nil
	}
	session.TempFile.Close()
	return os.Remove(session.TempFile.Name())
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

package gitstorage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ER-brocode/nexus-git-registry/pkg/oci"
)

var (
	ErrTagNotFound       = errors.New("tag reference not found")
	ErrManifestNotValid  = errors.New("manifest JSON invalid")
	ErrSignatureMismatch = errors.New("signature verification failed")
)

// GitRegistry tracks manifests and cryptographic Cosign/Notary signatures using Git commits and tree objects.
type GitRegistry struct {
	mu       sync.RWMutex
	repoDir  string
	author   string
	email    string
	pubKey   ed25519.PublicKey
	privKey  ed25519.PrivateKey
}

// ManifestRecord represents metadata persisted in git tree per tag.
type ManifestRecord struct {
	Repo         string            `json:"repo"`
	Tag          string            `json:"tag"`
	Digest       string            `json:"digest"`
	MediaType    string            `json:"mediaType"`
	Size         int64             `json:"size"`
	ConfigDigest string            `json:"configDigest"`
	LayerDigests []string          `json:"layerDigests"`
	PushedAt     time.Time         `json:"pushedAt"`
	Signatures   []SignatureMeta   `json:"signatures,omitempty"`
}

// SignatureMeta describes a cryptographically verified signature attached to an image digest.
type SignatureMeta struct {
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"publicKey"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signedAt"`
	Signer    string    `json:"signer"`
}

// NewGitRegistry initializes Git-backed metadata storage with auto-generated signing keys.
func NewGitRegistry(repoDir string) (*GitRegistry, error) {
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create git registry dir: %w", err)
	}

	// Initialize git repo if not already present
	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cmd := exec.Command("git", "init", "-b", "main")
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git init failed: %v, output: %s", err, string(out))
		}

		// Configure local git repo
		exec.Command("git", "-C", repoDir, "config", "user.name", "koushik4475").Run()
		exec.Command("git", "-C", repoDir, "config", "user.email", "koushik4475@gmail.com").Run()
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	return &GitRegistry{
		repoDir: repoDir,
		author:  "koushik4475",
		email:   "koushik4475@gmail.com",
		pubKey:  pub,
		privKey: priv,
	}, nil
}

// PublicKeyHex returns the hex-encoded Ed25519 public key.
func (g *GitRegistry) PublicKeyHex() string {
	return hex.EncodeToString(g.pubKey)
}

// PutManifest stores an OCI manifest in the git storage tree and records a git commit.
func (g *GitRegistry) PutManifest(repo, reference string, rawManifest []byte, mediaType string) (*ManifestRecord, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	parsed, digest, err := oci.ParseManifest(rawManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	// Directory hierarchy: refs/heads/manifests/<repo>/
	repoClean := strings.Trim(filepath.Clean(repo), "/\\")
	targetDir := filepath.Join(g.repoDir, "manifests", repoClean)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create repo manifest dir: %w", err)
	}

	// 1. Store by digest: <repo>/sha256_<hash>.json
	hashOnly := strings.TrimPrefix(digest, "sha256:")
	digestFile := filepath.Join(targetDir, fmt.Sprintf("sha256_%s.json", hashOnly))
	if err := os.WriteFile(digestFile, rawManifest, 0644); err != nil {
		return nil, fmt.Errorf("failed to write raw manifest: %w", err)
	}

	// 2. Prepare layer digest list
	var layers []string
	for _, l := range parsed.Layers {
		layers = append(layers, l.Digest)
	}

	rec := ManifestRecord{
		Repo:         repo,
		Tag:          reference,
		Digest:       digest,
		MediaType:    mediaType,
		Size:         int64(len(rawManifest)),
		ConfigDigest: parsed.Config.Digest,
		LayerDigests: layers,
		PushedAt:     time.Now().UTC(),
	}

	// 3. Store tag link metadata: <repo>/tags/<tag>.json
	if !strings.HasPrefix(reference, "sha256:") {
		tagsDir := filepath.Join(targetDir, "tags")
		if err := os.MkdirAll(tagsDir, 0755); err != nil {
			return nil, err
		}
		tagFile := filepath.Join(tagsDir, reference+".json")
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(tagFile, data, 0644); err != nil {
			return nil, err
		}
	}

	// Automatically sign the manifest record
	sig := ed25519.Sign(g.privKey, []byte(digest))
	sigMeta := SignatureMeta{
		Algorithm: "ed25519",
		PublicKey: hex.EncodeToString(g.pubKey),
		Signature: hex.EncodeToString(sig),
		SignedAt:  time.Now().UTC(),
		Signer:    g.author,
	}
	rec.Signatures = append(rec.Signatures, sigMeta)

	// 4. Commit to git storage
	commitMsg := fmt.Sprintf("chore(registry): push %s:%s [%s]", repo, reference, digest[:19])
	_ = g.gitCommit(commitMsg)

	return &rec, nil
}

// GetManifest retrieves raw manifest bytes by tag or sha256 digest.
func (g *GitRegistry) GetManifest(repo, reference string) ([]byte, string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	repoClean := strings.Trim(filepath.Clean(repo), "/\\")
	targetDir := filepath.Join(g.repoDir, "manifests", repoClean)

	if strings.HasPrefix(reference, "sha256:") {
		hashOnly := strings.TrimPrefix(reference, "sha256:")
		digestFile := filepath.Join(targetDir, fmt.Sprintf("sha256_%s.json", hashOnly))
		data, err := os.ReadFile(digestFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", ErrTagNotFound
			}
			return nil, "", err
		}
		return data, reference, nil
	}

	// Tag lookup
	tagFile := filepath.Join(targetDir, "tags", reference+".json")
	tagData, err := os.ReadFile(tagFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", ErrTagNotFound
		}
		return nil, "", err
	}

	var rec ManifestRecord
	if err := json.Unmarshal(tagData, &rec); err != nil {
		return nil, "", err
	}

	hashOnly := strings.TrimPrefix(rec.Digest, "sha256:")
	digestFile := filepath.Join(targetDir, fmt.Sprintf("sha256_%s.json", hashOnly))
	data, err := os.ReadFile(digestFile)
	if err != nil {
		return nil, "", err
	}

	return data, rec.Digest, nil
}

// ListTags lists all tags associated with a repository.
func (g *GitRegistry) ListTags(repo string) ([]string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	repoClean := strings.Trim(filepath.Clean(repo), "/\\")
	tagsDir := filepath.Join(g.repoDir, "manifests", repoClean, "tags")

	entries, err := os.ReadDir(tagsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var tags []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			tags = append(tags, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	return tags, nil
}

// SignManifest signs a given digest with an Ed25519 private key and stores in Git.
func (g *GitRegistry) SignManifest(repo, digest string, signerName string) (*SignatureMeta, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	sig := ed25519.Sign(g.privKey, []byte(digest))
	sigMeta := SignatureMeta{
		Algorithm: "ed25519",
		PublicKey: hex.EncodeToString(g.pubKey),
		Signature: hex.EncodeToString(sig),
		SignedAt:  time.Now().UTC(),
		Signer:    signerName,
	}

	repoClean := strings.Trim(filepath.Clean(repo), "/\\")
	sigDir := filepath.Join(g.repoDir, "manifests", repoClean, "signatures")
	if err := os.MkdirAll(sigDir, 0755); err != nil {
		return nil, err
	}

	hashOnly := strings.TrimPrefix(digest, "sha256:")
	sigFile := filepath.Join(sigDir, fmt.Sprintf("sha256_%s.sig.json", hashOnly))

	data, err := json.MarshalIndent(sigMeta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(sigFile, data, 0644); err != nil {
		return nil, err
	}

	g.gitCommit(fmt.Sprintf("chore(security): sign %s [%s]", repo, digest[:19]))
	return &sigMeta, nil
}

// VerifySignature verifies an Ed25519 signature payload for a digest.
func (g *GitRegistry) VerifySignature(digest string, sigMeta *SignatureMeta) (bool, error) {
	pubBytes, err := hex.DecodeString(sigMeta.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 public key length")
	}

	sigBytes, err := hex.DecodeString(sigMeta.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	valid := ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(digest), sigBytes)
	return valid, nil
}

// gitCommit stages manifest changes and produces a git commit.
func (g *GitRegistry) gitCommit(message string) error {
	addCmd := exec.Command("git", "-C", g.repoDir, "add", "-A")
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add failed: %s", string(out))
	}

	commitCmd := exec.Command("git", "-C", g.repoDir, "commit", "-m", message, "--allow-empty")
	if out, err := commitCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit failed: %s", string(out))
	}

	return nil
}

// CommitLog retrieves the recent commit messages from the Git storage repository.
func (g *GitRegistry) CommitLog(n int) ([]string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	cmd := exec.Command("git", "-C", g.repoDir, "log", fmt.Sprintf("-n%d", n), "--pretty=format:%h %s")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines, nil
}

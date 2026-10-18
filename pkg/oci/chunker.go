package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Chunk represents a content-defined deduplicated byte segment of a layer.
type Chunk struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Digest string `json:"digest"`
}

// FastCDC implements Content-Defined Chunking using normalized gear-hash algorithm.
type FastCDC struct {
	minSize  int
	avgSize  int
	maxSize  int
	maskS    uint32
	maskL    uint32
	gearTab  [256]uint32
}

// NewFastCDC initializes a FastCDC chunker with configured byte sizes.
func NewFastCDC(minSize, avgSize, maxSize int) *FastCDC {
	cdc := &FastCDC{
		minSize: minSize,
		avgSize: avgSize,
		maxSize: maxSize,
	}
	cdc.initGear()
	cdc.maskS = 0x0003ffff // mask for small chunk region
	cdc.maskL = 0x00007fff // mask for normal region
	return cdc
}

func (cdc *FastCDC) initGear() {
	// 256 precomputed deterministic gear hashes
	var seed uint32 = 0x811c9dc5
	for i := 0; i < 256; i++ {
		seed = seed*16777619 ^ uint32(i*31+17)
		cdc.gearTab[i] = seed
	}
}

// ChunkBuffer scans a raw byte slice into content-defined chunks with sha256 digests.
func (cdc *FastCDC) ChunkBuffer(data []byte) []Chunk {
	var chunks []Chunk
	n := len(data)
	if n == 0 {
		return chunks
	}

	offset := 0
	for offset < n {
		remaining := n - offset
		if remaining <= cdc.minSize {
			h := sha256.Sum256(data[offset:])
			chunks = append(chunks, Chunk{
				Offset: int64(offset),
				Length: int64(remaining),
				Digest: "sha256:" + hex.EncodeToString(h[:]),
			})
			break
		}

		chunkLen := cdc.findBoundary(data[offset:])
		h := sha256.Sum256(data[offset : offset+chunkLen])
		chunks = append(chunks, Chunk{
			Offset: int64(offset),
			Length: int64(chunkLen),
			Digest: "sha256:" + hex.EncodeToString(h[:]),
		})
		offset += chunkLen
	}

	return chunks
}

func (cdc *FastCDC) findBoundary(buf []byte) int {
	n := len(buf)
	if n > cdc.maxSize {
		n = cdc.maxSize
	}
	if n <= cdc.minSize {
		return n
	}

	var fp uint32 = 0
	mid := cdc.avgSize
	if mid > n {
		mid = n
	}

	// Phase 1: Small chunk boundary test
	for i := cdc.minSize; i < mid; i++ {
		fp = (fp << 1) + cdc.gearTab[buf[i]]
		if (fp & cdc.maskS) == 0 {
			return i + 1
		}
	}

	// Phase 2: Large chunk boundary test
	for i := mid; i < n; i++ {
		fp = (fp << 1) + cdc.gearTab[buf[i]]
		if (fp & cdc.maskL) == 0 {
			return i + 1
		}
	}

	return n
}

// DeduplicationIndex tracks distinct chunks across multiple image layers.
type DeduplicationIndex struct {
	chunks map[string]int64 // digest -> size
	totalRawBytes    int64
	totalUniqueBytes int64
}

// NewDeduplicationIndex creates an in-memory chunk deduplication index.
func NewDeduplicationIndex() *DeduplicationIndex {
	return &DeduplicationIndex{
		chunks: make(map[string]int64),
	}
}

// RecordChunk registers a chunk and returns true if it is completely novel.
func (idx *DeduplicationIndex) RecordChunk(c Chunk) bool {
	idx.totalRawBytes += c.Length
	if _, exists := idx.chunks[c.Digest]; exists {
		return false
	}
	idx.chunks[c.Digest] = c.Length
	idx.totalUniqueBytes += c.Length
	return true
}

// Stats returns the raw bytes, deduplicated unique bytes, and savings percentage.
func (idx *DeduplicationIndex) Stats() (int64, int64, float64) {
	if idx.totalRawBytes == 0 {
		return 0, 0, 0.0
	}
	savings := float64(idx.totalRawBytes-idx.totalUniqueBytes) / float64(idx.totalRawBytes) * 100.0
	return idx.totalRawBytes, idx.totalUniqueBytes, savings
}

// StreamChunks reads stream r and yields chunk boundaries.
func (cdc *FastCDC) StreamChunks(r io.Reader) ([]Chunk, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return cdc.ChunkBuffer(data), nil
}

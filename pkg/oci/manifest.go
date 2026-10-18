package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Standard OCI Media Types
const (
	MediaTypeDescriptor             = "application/vnd.oci.descriptor.v1+json"
	MediaTypeImageManifest          = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeImageIndex             = "application/vnd.oci.image.index.v1+json"
	MediaTypeImageConfig            = "application/vnd.oci.image.config.v1+json"
	MediaTypeImageLayer             = "application/vnd.oci.image.layer.v1.tar"
	MediaTypeImageLayerGzip         = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaTypeImageLayerZstd         = "application/vnd.oci.image.layer.v1.tar+zstd"
	MediaTypeEmptyJSON              = "application/vnd.oci.empty.v1+json"
	MediaTypeDockerManifestSchema2  = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerLayerGzip        = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	MediaTypeDockerConfigJSON       = "application/vnd.docker.container.image.v1+json"
)

var (
	ErrInvalidDigest   = errors.New("oci: invalid digest format")
	ErrDigestMismatch  = errors.New("oci: content digest does not match expected digest")
	ErrInvalidManifest = errors.New("oci: invalid manifest structure")
)

// Descriptor describes targeted content in terms of media type, digest, and byte size.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Data        []byte            `json:"data,omitempty"`
}

// Manifest represents an OCI Image Manifest (Schema v2).
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Index represents an OCI Image Index / Multi-arch manifest list.
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// ImageConfig represents the runtime configuration for a container image.
type ImageConfig struct {
	Created      *time.Time        `json:"created,omitempty"`
	Author       string            `json:"author,omitempty"`
	Architecture string            `json:"architecture"`
	OS           string            `json:"os"`
	Config       ContainerConfig   `json:"config"`
	RootFS       RootFS            `json:"rootfs"`
	History      []HistoryRecord   `json:"history,omitempty"`
}

// ContainerConfig holds configuration options for running a container.
type ContainerConfig struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	StopSignal   string              `json:"StopSignal,omitempty"`
}

// RootFS contains references to the diff IDs comprising the image filesystem.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// HistoryRecord describes a build layer or step.
type HistoryRecord struct {
	Created    *time.Time `json:"created,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	Author     string     `json:"author,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	EmptyLayer bool       `json:"empty_layer,omitempty"`
}

// ValidateDigest checks if a string is a valid algorithm:hex digest.
func ValidateDigest(digest string) error {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) == 0 {
		return ErrInvalidDigest
	}
	if parts[0] == "sha256" && len(parts[1]) != 64 {
		return fmt.Errorf("%w: sha256 hex must be 64 characters", ErrInvalidDigest)
	}
	_, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: non-hex characters in digest", ErrInvalidDigest)
	}
	return nil
}

// ComputeSHA256 returns the formatted "sha256:<hex>" digest of arbitrary bytes.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ParseManifest parses and validates raw JSON manifest bytes into a Manifest struct.
func ParseManifest(data []byte) (*Manifest, string, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if m.SchemaVersion != 2 {
		return nil, "", fmt.Errorf("%w: unsupported schemaVersion %d", ErrInvalidManifest, m.SchemaVersion)
	}
	if m.Config.Digest == "" {
		return nil, "", fmt.Errorf("%w: missing config descriptor", ErrInvalidManifest)
	}
	if err := ValidateDigest(m.Config.Digest); err != nil {
		return nil, "", fmt.Errorf("invalid config digest: %w", err)
	}
	for i, layer := range m.Layers {
		if err := ValidateDigest(layer.Digest); err != nil {
			return nil, "", fmt.Errorf("layer[%d] invalid digest %s: %w", i, layer.Digest, err)
		}
	}
	digest := ComputeSHA256(data)
	return &m, digest, nil
}

// ParseIndex parses and validates an OCI Image Index JSON payload.
func ParseIndex(data []byte) (*Index, string, error) {
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, "", fmt.Errorf("invalid index: %w", err)
	}
	for i, m := range idx.Manifests {
		if err := ValidateDigest(m.Digest); err != nil {
			return nil, "", fmt.Errorf("index manifest[%d] invalid digest: %w", i, err)
		}
	}
	digest := ComputeSHA256(data)
	return &idx, digest, nil
}

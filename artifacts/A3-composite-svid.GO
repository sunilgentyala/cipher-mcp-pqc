
// Artifact A3: Composite SVID Generator (SPIFFE/SPIRE Workaround)
// CIPHER Framework -- ACM QSec 2026
// Author: Sunil Gentyala, HCLTech (gentyalas@hcltech.com)
// ORCID: 0009-0005-2642-3479
//
// Generates composite ML-DSA-65 + ECDSA-P256 leaf certificates with
// a SPIFFE URI in the SubjectAlternativeName extension, implementing
// the CSP workaround for the SPIFFE/SPIRE composite SVID gap.
//
// Identity binding guarantees:
//   - Both credentials contain the same SPIFFE URI in SAN
//   - MCP server verifies both URIs match before accepting the pair
//   - Composite cert validity period must not exceed SPIRE SVID TTL
//   - Rotation daemon monitors SPIRE Workload API for SVID renewal events
//
// Usage:
//   go run composite_svid_gen.go \
//     --spiffe-id spiffe://example.com/agent/my-agent \
//     --output ./certs/ \
//     --ttl 24h
//
// Requirements:
//   go get github.com/open-quantum-safe/liboqs-go
//   go get github.com/spiffe/go-spiffe/v2

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// CompositeKeyPair holds both the ML-DSA-65 (PQ) and ECDSA-P256 (traditional)
// key pairs that together form the composite SVID identity.
type CompositeKeyPair struct {
	// PQ component: ML-DSA-65 key material (raw bytes for now;
	// full liboqs-go integration requires CGO build tags)
	MLDSAPublicKey  []byte `json:"ml_dsa_public_key_b64"`
	MLDSAPrivateKey []byte `json:"-"`

	// Traditional component: ECDSA-P256
	ECDSAKey *ecdsa.PrivateKey
}

// JWKDocument is the output JWK Set containing both public keys
type JWKDocument struct {
	Keys []map[string]interface{} `json:"keys"`
}

func generateCompositeKeyPair() (*CompositeKeyPair, error) {
	// ECDSA-P256 key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA-P256 key: %w", err)
	}

	// ML-DSA-65 placeholder: in production, call liboqs-go OQS_KEM/OQS_SIG.
	// Stubbed here to maintain portability without CGO build constraints.
	// Replace mldsaPublicKey and mldsaPrivateKey with:
	//   signer, _ := liboqs.NewSig("ML-DSA-65")
	//   pubKey, privKey, _ := signer.GenerateKeypair()
	mldsaPublicKey := make([]byte, 1952) // ML-DSA-65 public key is always 1,952 bytes
	if _, err := rand.Read(mldsaPublicKey); err != nil {
		return nil, fmt.Errorf("generating ML-DSA-65 stub key: %w", err)
	}
	mldsaPrivateKey := make([]byte, 4032) // ML-DSA-65 private key is always 4,032 bytes
	if _, err := rand.Read(mldsaPrivateKey); err != nil {
		return nil, fmt.Errorf("generating ML-DSA-65 stub private key: %w", err)
	}

	return &CompositeKeyPair{
		MLDSAPublicKey:  mldsaPublicKey,
		MLDSAPrivateKey: mldsaPrivateKey,
		ECDSAKey:        ecKey,
	}, nil
}

func buildX509Template(spiffeID string, ttl time.Duration) (*x509.Certificate, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parsing SPIFFE ID: %w", err)
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("SPIFFE ID must use spiffe:// scheme, got: %s", u.Scheme)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"CIPHER MCP Workload Identity"},
			CommonName:   spiffeID,
		},
		URIs:      []*url.URL{u},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}, nil
}

func writePEM(path string, blockType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}

func main() {
	var (
		spiffeID  = flag.String("spiffe-id", "", "SPIFFE URI (e.g. spiffe://example.com/agent/name)")
		outputDir = flag.String("output", "./certs", "Directory to write output files")
		ttlStr    = flag.String("ttl", "24h", "Certificate TTL (e.g. 72h)")
	)
	flag.Parse()

	if *spiffeID == "" {
		log.Fatal("--spiffe-id is required")
	}
	ttl, err := time.ParseDuration(*ttlStr)
	if err != nil {
		log.Fatalf("invalid --ttl: %v", err)
	}

	if err := os.MkdirAll(*outputDir, 0700); err != nil {
		log.Fatalf("creating output directory: %v", err)
	}

	log.Printf("Generating composite SVID for SPIFFE ID: %s", *spiffeID)
	log.Printf("TTL: %s | Output: %s", ttl, *outputDir)

	// Generate key pair
	kp, err := generateCompositeKeyPair()
	if err != nil {
		log.Fatalf("generating composite key pair: %v", err)
	}

	// Build X.509 template
	tmpl, err := buildX509Template(*spiffeID, ttl)
	if err != nil {
		log.Fatalf("building certificate template: %v", err)
	}

	// Self-sign with ECDSA-P256 (production: sign with separate PKI CA)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &kp.ECDSAKey.PublicKey, kp.ECDSAKey)
	if err != nil {
		log.Fatalf("creating X.509 certificate: %v", err)
	}

	// Write ECDSA certificate PEM
	certPath := filepath.Join(*outputDir, "composite-svid.pem")
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		log.Fatalf("writing certificate: %v", err)
	}
	log.Printf("Certificate written: %s", certPath)

	// Write ECDSA private key PEM
	ecKeyDER, err := x509.MarshalECPrivateKey(kp.ECDSAKey)
	if err != nil {
		log.Fatalf("marshaling ECDSA key: %v", err)
	}
	keyPath := filepath.Join(*outputDir, "composite-svid.key")
	if err := writePEM(keyPath, "EC PRIVATE KEY", ecKeyDER); err != nil {
		log.Fatalf("writing private key: %v", err)
	}
	log.Printf("Private key written: %s", keyPath)

	// Write JWK document containing both public keys
	// Note: IANA JOSE alg identifier for ML-DSA-65 pending draft-ietf-cose-dilithium-11
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&kp.ECDSAKey.PublicKey)
	jwk := JWKDocument{
		Keys: []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"alg": "ES256",
				"use": "sig",
				"x5u": *spiffeID,
				"kid": fmt.Sprintf("%s-ecdsa", *spiffeID),
				"x509_der_b64": fmt.Sprintf("%x", ecPubDER),
			},
			{
				// ML-DSA-65 JOSE alg identifier: provisional pending IANA registration
				// per draft-ietf-cose-dilithium-11 (Standards Track, Nov 2025)
				"kty": "AKP",
				"alg": "ML-DSA-65",
				"use": "sig",
				"x5u": *spiffeID,
				"kid": fmt.Sprintf("%s-mldsa65", *spiffeID),
				"pub_hex": fmt.Sprintf("%x", kp.MLDSAPublicKey),
				"note":    "STUB: replace with liboqs-go generated key in production",
			},
		},
	}
	jwkPath := filepath.Join(*outputDir, "composite-svid.jwks")
	jwkData, _ := json.MarshalIndent(jwk, "", "  ")
	if err := os.WriteFile(jwkPath, jwkData, 0600); err != nil {
		log.Fatalf("writing JWK document: %v", err)
	}
	log.Printf("JWK document written: %s", jwkPath)

	log.Printf("\nIdentity binding summary:")
	log.Printf("  SPIFFE URI in SAN: %s", *spiffeID)
	log.Printf("  Valid until:       %s UTC", tmpl.NotAfter.UTC().Format(time.RFC3339))
	log.Printf("  ECDSA-P256 key:    %s", certPath)
	log.Printf("  ML-DSA-65 key:     %s (stub -- replace with liboqs-go)", jwkPath)
	log.Printf("\nNote: SPIRE SVID TTL must be >= certificate TTL (%s) for rotation sync.", ttl)
	log.Printf("Run --ttl to match your SPIRE agent configuration.")
}

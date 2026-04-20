
# cipher-mcp-pqc# CIPHER-MCP-PQC

**Composite Identity, Protocol Handshake, and Evidence Repository**
Hybrid post-quantum governance framework for Model Context Protocol infrastructure.

Accompanies: *Composite Trust for Cognitive Workloads: Hybrid Post-Quantum Identity and Handshake Hardening for AI Agent Protocols* — ACM QSec 2026 / Elsevier FGCS 2026.

**Author:** Sunil Gentyala, HCLTech | IEEE Senior Member 101760715 | ORCID 0009-0005-2642-3479

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)

---

## Repository Structure

```
cipher-mcp-pqc/
├── artifacts/
│   ├── A1-HHF-enforcer/          Layer 1: Hybrid Handshake Floor
│   │   ├── openssl-hybrid.conf   OpenSSL 3.5 config for X25519MLKEM768
│   │   └── hhf_monitor.py        TLS session compliance monitor + middlebox probe
│   ├── A2-CCRS-evaluator/        Layer 2: Composite Certificate Readiness Score
│   │   └── ccrs_score.py         Certificate chain evaluator (score 0-5)
│   ├── A3-composite-svid/        Layer 3: Composite SVID Policy (SPIFFE workaround)
│   │   └── composite_svid_gen.go ML-DSA-65 + ECDSA-P256 SVID generator (Go)
│   └── A4-HRSP-middleware/       Layer 4: Hybrid Result Signature Policy
│       └── hrsp_middleware.py    Detached ML-DSA-65 result signature verifier
├── benchmarks/
│   ├── harness/                  Go MCP stub server and bench client
│   └── results_raw.csv           50,000-run handshake benchmark dataset
├── paper/
│   ├── ACM_CIPHER_v5_ACMTemplate.docx
│   └── FGCS_CIPHER_FINAL_v3.docx
├── CITATION.cff
├── LICENSE
└── README.md
```

## CIPHER Framework Controls

| Control | Layer | Addresses | Policy Tiers |
|---------|-------|-----------|--------------|
| HHF | TLS key exchange | V1: Quantum-vulnerable handshake | Monitor / Prefer / Require |
| CCRS | Certificate PKI | V2: Single-algorithm X.509 certs | Score 0-5 per endpoint |
| CSP | Workload identity | V3: Classical SPIFFE/SPIRE SVIDs | Monitor / Prefer / Require |
| HRSP | Tool result provenance | V4: Unsigned tool results | Monitor / Prefer / Require |

## Quick Start

### A1: HHF Enforcer

```bash
# Check compliance from TLS session logs
pip install -r artifacts/A1-HHF-enforcer/requirements.txt
python artifacts/A1-HHF-enforcer/hhf_monitor.py \
    --log /var/log/mcp/tls.log \
    --probe mcp.example.com \
    --output report.json
```

### A2: CCRS Evaluator

```bash
pip install cryptography pyopenssl
python artifacts/A2-CCRS-evaluator/ccrs_score.py \
    --host mcp.example.com --port 443
```

Output example:
```
CIPHER CCRS Evaluation
Host:        mcp.example.com:443
CCRS Score:  3 / 5
Rationale:   PQ intermediate detected. Parallel PKI deployment. Root remains quantum-vulnerable.
Chain depth: 3
Chain:
  [0] Leaf:         mcp.example.com (traditional)
  [1] Intermediate: Corp CA (ML-DSA-65)
  [2] Root:         Corp Root (traditional)
```

### A3: Composite SVID Generator

```bash
go run artifacts/A3-composite-svid/composite_svid_gen.go \
    --spiffe-id spiffe://example.com/agent/research-agent \
    --output ./certs/ \
    --ttl 24h
```

**Important:** For production use, replace the ML-DSA-65 stub key generation
with `liboqs-go` (github.com/open-quantum-safe/liboqs-go). The stub uses
random bytes of the correct length (1,952-byte public key, 4,032-byte private
key per FIPS 204) to allow pipeline testing without CGO build requirements.

Identity binding: both the SPIRE-issued SVID and the composite certificate
must contain the same SPIFFE URI in the Subject Alternative Name extension.
The MCP server verifies both URIs match before accepting the credential pair.

### A4: HRSP Middleware

```bash
pip install -r artifacts/A4-HRSP-middleware/requirements.txt

# Monitor mode (no enforcement, collect metrics)
python artifacts/A4-HRSP-middleware/hrsp_middleware.py \
    --mode monitor --port 8080 --upstream http://mcp-server:8000

# Prefer mode (flag unsigned, allow through with warning)
python artifacts/A4-HRSP-middleware/hrsp_middleware.py \
    --mode prefer --port 8080 --upstream http://mcp-server:8000

# Require mode (EXPERIMENTAL: unsigned results quarantined)
# Only use after draft-ietf-cose-dilithium-11 reaches RFC status
python artifacts/A4-HRSP-middleware/hrsp_middleware.py \
    --mode require --port 8080 --upstream http://mcp-server:8000
```

## Standards Referenced

| Standard | Status | Use in CIPHER |
|----------|--------|---------------|
| FIPS 203 (ML-KEM) | Finalized Aug 2024 | A1: HHF key exchange |
| FIPS 204 (ML-DSA) | Finalized Aug 2024 | A3: SVID, A4: HRSP |
| FIPS 205 (SLH-DSA) | Finalized Aug 2024 | A2: CCRS offline CA roots |
| RFC 9794 | Published Jun 2025 | Framework taxonomy |
| draft-ietf-tls-ecdhe-mlkem-04 | RFC Editor queue | A1: X25519MLKEM768 |
| draft-ietf-lamps-pq-composite-sigs-16 | Standards Track | A2: CCRS scoring |
| draft-ietf-cose-dilithium-11 | Standards Track | A4: HRSP alg identifiers (EXPERIMENTAL) |

## Citation

```bibtex
@software{gentyala2026cipher,
  author    = {Gentyala, Sunil},
  title     = {CIPHER-MCP-PQC: Hybrid Post-Quantum Governance for MCP},
  year      = {2026},
  version   = {v1.0.0},
  doi       = {10.5281/zenodo.XXXXXXX},
  url       = {https://github.com/sunilgentyala/cipher-mcp-pqc},
  orcid     = {0009-0005-2642-3479}
}

@inproceedings{gentyala2026composite,
  author    = {Gentyala, Sunil},
  title     = {Composite Trust for Cognitive Workloads: Hybrid Post-Quantum Identity
               and Handshake Hardening for {AI} Agent Protocols},
  booktitle = {Proceedings of the ACM Workshop on Post-Quantum Cryptography Security (QSec '26)},
  year      = {2026},
  publisher = {ACM},
  doi       = {10.1145/XXXXXXX.XXXXXXX}
}
```

## License

MIT License. See LICENSE for details.

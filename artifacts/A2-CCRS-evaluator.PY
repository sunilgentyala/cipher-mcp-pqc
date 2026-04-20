
#!/usr/bin/env python3
"""
Artifact A2: Composite Certificate Readiness Score (CCRS) Evaluator
CIPHER Framework -- ACM QSec 2026
Author: Sunil Gentyala, HCLTech (gentyalas@hcltech.com)
ORCID: 0009-0005-2642-3479

Connects to any MCP server endpoint, retrieves its certificate chain,
and produces a CCRS score from 0 to 5 based on:
  Score 0: Traditional-only chain, no post-quantum component
  Score 1: PQ leaf cert within a traditionally-rooted chain
            (does NOT achieve hybrid authentication per RFC 9794 S6.1)
  Score 2: PQ intermediate cert, traditionally-rooted
  Score 3: Parallel PKI (both traditional and PQ chains available)
  Score 4: Composite leaf cert (ML-DSA+ECDSA) in traditional chain
  Score 5: Full composite chain to PQ root (complete hybrid authentication)

Usage:
    python ccrs_score.py --host mcp.example.com --port 443 [--json]

Requirements:
    pip install cryptography pyopenssl
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    import cryptography.hazmat.primitives.serialization as serialization
except ImportError:
    print("ERROR: Install cryptography: pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ML-DSA OIDs per draft-ietf-lamps-pq-composite-sigs-16
ML_DSA_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

# Composite OIDs (id-MLDSA*-ECDSA-* and id-MLDSA*-Ed25519)
COMPOSITE_OIDS = {
    "2.16.840.1.114027.80.8.1.1": "id-MLDSA44-RSA2048-PSS",
    "2.16.840.1.114027.80.8.1.2": "id-MLDSA44-RSA2048-PKCS15",
    "2.16.840.1.114027.80.8.1.3": "id-MLDSA44-Ed25519",
    "2.16.840.1.114027.80.8.1.4": "id-MLDSA44-ECDSA-P256",
    "2.16.840.1.114027.80.8.1.5": "id-MLDSA65-RSA3072-PSS",
    "2.16.840.1.114027.80.8.1.6": "id-MLDSA65-RSA3072-PKCS15",
    "2.16.840.1.114027.80.8.1.7": "id-MLDSA65-ECDSA-P384",
    "2.16.840.1.114027.80.8.1.8": "id-MLDSA65-ECDSA-P256",
    "2.16.840.1.114027.80.8.1.9": "id-MLDSA65-Ed25519",
    "2.16.840.1.114027.80.8.1.10": "id-MLDSA87-ECDSA-P384",
    "2.16.840.1.114027.80.8.1.11": "id-MLDSA87-ECDSA-P521",
    "2.16.840.1.114027.80.8.1.12": "id-MLDSA87-Ed448",
}

SLH_DSA_OIDS = {
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
}

ALL_PQ_OIDS = {**ML_DSA_OIDS, **COMPOSITE_OIDS, **SLH_DSA_OIDS}


def get_sig_alg_oid(cert: x509.Certificate) -> str:
    return cert.signature_algorithm_oid.dotted_string


def classify_cert(cert: x509.Certificate) -> dict:
    oid = get_sig_alg_oid(cert)
    is_composite = oid in COMPOSITE_OIDS
    is_pq_pure = oid in ML_DSA_OIDS or oid in SLH_DSA_OIDS
    is_traditional = not (is_composite or is_pq_pure)

    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = subject[0].value if subject else "unknown"
    is_self_signed = cert.issuer == cert.subject

    return {
        "cn": cn,
        "sig_oid": oid,
        "sig_name": ALL_PQ_OIDS.get(oid, "traditional"),
        "is_composite": is_composite,
        "is_pq_pure": is_pq_pure,
        "is_traditional": is_traditional,
        "is_root": is_self_signed,
    }


def fetch_chain(host: str, port: int) -> list:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der_chain = ssock.get_verified_chain() if hasattr(ssock, 'get_verified_chain') else []
            if not der_chain:
                der_cert = ssock.getpeercert(binary_form=True)
                return [x509.load_der_x509_certificate(der_cert, default_backend())]
            return [x509.load_der_x509_certificate(c, default_backend()) for c in der_chain]


def score_chain(chain_info: list) -> tuple[int, str]:
    if not chain_info:
        return 0, "No certificate chain retrieved"

    leaf = chain_info[0]
    root = chain_info[-1]
    intermediates = chain_info[1:-1]

    # Score 0: all traditional
    if leaf["is_traditional"] and root["is_traditional"]:
        return 0, "Traditional-only chain. No post-quantum component present."

    # Score 5: full composite chain to PQ root
    if (leaf["is_composite"] and root["is_composite"]):
        return 5, f"Full composite chain. Leaf: {leaf['sig_name']}. Root: {root['sig_name']}. Complete hybrid authentication per RFC 9794."

    # Score 4: composite leaf, traditional root
    if leaf["is_composite"] and root["is_traditional"]:
        return 4, f"Composite leaf ({leaf['sig_name']}) within traditional root chain. Leaf provides hybrid auth but root remains quantum-vulnerable (RFC 9794 S6.1 applies)."

    # Score 3: parallel PKI detected (check for dual SAN or second chain indicator)
    # In practice Score 3 is self-reported by checking two independent chains
    # We approximate: if any intermediate is PQ and root is traditional
    if any(c["is_pq_pure"] or c["is_composite"] for c in intermediates) and root["is_traditional"]:
        return 3, f"PQ intermediate detected in traditionally-rooted chain. May indicate parallel PKI deployment. Root remains quantum-vulnerable."

    # Score 2: PQ intermediate, traditional root and leaf
    if any(c["is_pq_pure"] for c in intermediates) and leaf["is_traditional"]:
        return 2, f"PQ intermediate but traditional leaf and root. Partial migration."

    # Score 1: PQ leaf only in traditional chain
    if leaf["is_pq_pure"] and root["is_traditional"]:
        return 1, f"PQ-pure leaf ({leaf['sig_name']}) in traditional root chain. Does NOT achieve hybrid authentication per RFC 9794 Section 6.1. The traditional CA root remains the binding trust anchor."

    return 0, "Unable to classify chain -- defaulting to Score 0."


def main():
    parser = argparse.ArgumentParser(
        description="CIPHER CCRS Evaluator -- Composite Certificate Readiness Score"
    )
    parser.add_argument("--host", required=True, help="MCP server hostname")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default: 443)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--batch", help="File with one HOST:PORT per line")
    args = parser.parse_args()

    targets = []
    if args.batch:
        with open(args.batch) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(":")
                    targets.append((parts[0], int(parts[1]) if len(parts) > 1 else 443))
    else:
        targets = [(args.host, args.port)]

    results = []
    for host, port in targets:
        try:
            chain = fetch_chain(host, port)
            chain_info = [classify_cert(c) for c in chain]
            score, rationale = score_chain(chain_info)
            results.append({
                "host": host,
                "port": port,
                "ccrs_score": score,
                "rationale": rationale,
                "chain_depth": len(chain_info),
                "chain_summary": [{"cn": c["cn"], "sig": c["sig_name"]} for c in chain_info],
                "evaluated_at": datetime.utcnow().isoformat() + "Z",
            })
        except Exception as e:
            results.append({
                "host": host, "port": port,
                "ccrs_score": -1,
                "rationale": f"Evaluation failed: {e}",
                "evaluated_at": datetime.utcnow().isoformat() + "Z",
            })

    if args.json or args.batch:
        print(json.dumps({"control": "CCRS", "results": results}, indent=2))
    else:
        r = results[0]
        print(f"\nCIPHER CCRS Evaluation")
        print(f"Host:        {r['host']}:{r['port']}")
        print(f"CCRS Score:  {r['ccrs_score']} / 5")
        print(f"Rationale:   {r['rationale']}")
        print(f"Chain depth: {r.get('chain_depth', 'N/A')}")
        if "chain_summary" in r:
            print("Chain:")
            for i, c in enumerate(r["chain_summary"]):
                role = "Leaf" if i == 0 else ("Root" if i == len(r["chain_summary"])-1 else "Intermediate")
                print(f"  [{i}] {role}: {c['cn']} ({c['sig']})")


if __name__ == "__main__":
    main()

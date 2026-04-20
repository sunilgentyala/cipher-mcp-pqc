
#!/usr/bin/env python3
"""
Artifact A1: Hybrid Handshake Floor (HHF) Compliance Monitor
CIPHER Framework -- ACM QSec 2026
Author: Sunil Gentyala, HCLTech (gentyalas@hcltech.com)
ORCID: 0009-0005-2642-3479

Parses MCP server TLS session negotiation logs and produces per-server
HHF compliance rates. Identifies connections that fell back to
traditional-only cipher suites and flags them for remediation.

Usage:
    python hhf_monitor.py --log /var/log/mcp/tls.log --output report.json

Log format expected (one line per connection):
    TIMESTAMP SERVER_FQDN CLIENT_IP CIPHER_SUITE KE_GROUP STATUS_CODE
    2026-04-19T10:23:01Z mcp.example.com 10.0.1.5 TLS_AES_256_GCM X25519MLKEM768 200
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime


HYBRID_GROUPS = {
    "X25519MLKEM768",      # 0x11EC per draft-ietf-tls-ecdhe-mlkem-04
    "SecP256r1MLKEM768",   # 0x11EB
    "SecP384r1MLKEM1024",  # 0x11ED
}

TRADITIONAL_ONLY_GROUPS = {
    "X25519", "P-256", "P-384", "P-521",
    "secp256r1", "secp384r1", "secp521r1",
}


def parse_log_line(line: str) -> dict | None:
    parts = line.strip().split()
    if len(parts) < 6:
        return None
    return {
        "timestamp": parts[0],
        "server": parts[1],
        "client_ip": parts[2],
        "cipher": parts[3],
        "ke_group": parts[4],
        "status": parts[5],
    }


def analyze_log(log_path: str) -> dict:
    stats = defaultdict(lambda: {
        "total": 0,
        "hybrid": 0,
        "traditional_fallback": 0,
        "unknown": 0,
        "compliance_rate": 0.0,
        "fallback_ips": [],
    })

    with open(log_path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            record = parse_log_line(line)
            if not record:
                continue
            server = record["server"]
            ke = record["ke_group"]
            stats[server]["total"] += 1

            if ke in HYBRID_GROUPS:
                stats[server]["hybrid"] += 1
            elif ke in TRADITIONAL_ONLY_GROUPS:
                stats[server]["traditional_fallback"] += 1
                stats[server]["fallback_ips"].append(record["client_ip"])
            else:
                stats[server]["unknown"] += 1

    for server, s in stats.items():
        if s["total"] > 0:
            s["compliance_rate"] = round(s["hybrid"] / s["total"] * 100, 1)
        # Deduplicate fallback IPs
        s["fallback_ips"] = list(set(s["fallback_ips"]))

    return dict(stats)


def middlebox_probe(server_fqdn: str, port: int = 443) -> dict:
    """
    Probes whether X25519MLKEM768 ClientHello fragments correctly through
    the network path to the target MCP server.
    Returns a dict with success flag and failure reason.
    Requires: openssl 3.5+ on PATH.
    """
    import subprocess
    import shutil

    if not shutil.which("openssl"):
        return {"probed": False, "reason": "openssl not found on PATH"}

    cmd = [
        "openssl", "s_client",
        "-connect", f"{server_fqdn}:{port}",
        "-groups", "X25519MLKEM768",
        "-brief",
        "-quiet",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            input=""
        )
        output = result.stdout + result.stderr
        if "X25519MLKEM768" in output:
            return {"probed": True, "hybrid_negotiated": True, "reason": ""}
        elif "handshake failure" in output.lower():
            return {"probed": True, "hybrid_negotiated": False,
                    "reason": "Handshake failed -- likely middlebox fragmentation"}
        else:
            return {"probed": True, "hybrid_negotiated": False,
                    "reason": f"Unexpected response: {output[:120]}"}
    except subprocess.TimeoutExpired:
        return {"probed": False, "reason": "Connection timed out"}


def main():
    parser = argparse.ArgumentParser(
        description="CIPHER HHF Compliance Monitor"
    )
    parser.add_argument("--log", required=True, help="TLS session log file")
    parser.add_argument("--output", default="-", help="Output JSON file (- for stdout)")
    parser.add_argument("--probe", nargs="*", metavar="FQDN",
                        help="Run middlebox probe against these MCP servers")
    args = parser.parse_args()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "cipher_framework": "CIPHER v1.0.0",
        "control": "HHF - Hybrid Handshake Floor",
        "servers": analyze_log(args.log),
    }

    if args.probe:
        report["middlebox_probes"] = {}
        for fqdn in args.probe:
            report["middlebox_probes"][fqdn] = middlebox_probe(fqdn)

    output = json.dumps(report, indent=2)
    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()

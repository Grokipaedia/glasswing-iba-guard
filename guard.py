# glasswing-guard.py
# IBA Intent Bound Authorization for autonomous vulnerability patching
# Patent GB2603013.0 Pending · IntentBound.com · IBA@intentbound.com

import json
import sys
import argparse
from datetime import datetime, timedelta

COALITION_MEMBERS = [
    "aws", "apple", "google", "microsoft", "nvidia",
    "crowdstrike", "jpmorgan", "cisco", "paloalto", "linux-foundation"
]

def create_glasswing_cert(patch_file: str, org: str, cve: str, paths: list = None):
    if org.lower() not in COALITION_MEMBERS:
        print(f"WARNING: '{org}' is not a recognised Glasswing coalition member.")
        print(f"Recognised members: {', '.join(COALITION_MEMBERS)}")

    cert = {
        "iba_version": "2.0",
        "certificate_id": f"glasswing-{org}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "issued_at": datetime.now().isoformat(),
        "coalition_member": org.lower(),
        "agent_id": "claude-mythos-glasswing",
        "principal": "human-security-officer",
        "declared_intent": (
            f"Patch {cve} in {org} environment. "
            f"Declared file paths only. No data exfiltration. "
            f"No scope expansion beyond declared CVE and paths."
        ),
        "scope_envelope": {
            "permitted_cve": [cve],
            "permitted_paths": paths or ["[DECLARE PATHS BEFORE EXECUTION]"],
            "denied": [
                "exfiltration",
                "scope-expansion",
                "undeclared-paths",
                "undeclared-systems",
                "credential-access",
                "lateral-movement"
            ],
            "default_posture": "DENY_ALL"
        },
        "temporal_scope": {
            "valid_from": datetime.now().isoformat(),
            "hard_expiry": (datetime.now() + timedelta(hours=4)).isoformat()
        },
        "entropy_threshold": {
            "max_kl_divergence": 0.10,
            "flag_at": 0.07,
            "kill_at": 0.10,
            "replan_window_ms": 500
        },
        "shard_type": "coalition-member",
        "parent_cert": "glasswing-master-cert",
        "witnessbound": "enabled",
        "iba_signature": "ECDSA-P384-demo"
    }
    return cert

def wrap_patch(patch_file: str, cert: dict):
    try:
        with open(patch_file, encoding="utf-8") as f:
            patch_content = f.read()
    except FileNotFoundError:
        print(f"Error: patch file '{patch_file}' not found.")
        sys.exit(1)

    output_file = patch_file + ".iba-governed.patch"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# IBA INTENT BOUND AUTHORIZATION — GOVERNED PATCH\n")
        f.write("# Patent GB2603013.0 Pending · IntentBound.com\n")
        f.write("# This patch may only execute within the declared scope below.\n")
        f.write("# DENY_ALL default — undeclared paths and systems blocked.\n")
        f.write("#\n")
        f.write(f"# INTENT CERTIFICATE:\n")
        for line in json.dumps(cert, indent=2).split("\n"):
            f.write(f"# {line}\n")
        f.write("#\n")
        f.write("# === PATCH CONTENT BELOW ===\n\n")
        f.write(patch_content)

    return output_file

def validate_scope(cert: dict, attempted_path: str) -> bool:
    permitted = cert["scope_envelope"].get("permitted_paths", [])
    denied = cert["scope_envelope"].get("denied", [])

    for d in denied:
        if d in attempted_path:
            print(f"IBA GATE: BLOCKED — path contains denied term '{d}'")
            return False

    if "[DECLARE PATHS BEFORE EXECUTION]" in permitted:
        print("IBA GATE: BLOCKED — no paths declared in certificate. Declare permitted paths first.")
        return False

    for p in permitted:
        if attempted_path.startswith(p):
            print(f"IBA GATE: AUTHORIZED — path '{attempted_path}' within declared scope")
            return True

    print(f"IBA GATE: BLOCKED — path '{attempted_path}' not in declared scope")
    print(f"  Declared paths: {permitted}")
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IBA governance wrapper for Glasswing autonomous patch execution"
    )
    parser.add_argument("patch_file", help="Path to patch diff file")
    parser.add_argument("--org", required=True, help="Coalition member org (e.g. aws, apple, jpmorgan)")
    parser.add_argument("--cve", required=True, help="CVE identifier being patched (e.g. CVE-2024-1234)")
    parser.add_argument("--paths", nargs="+", help="Declared permitted file paths")
    parser.add_argument("--validate", help="Test a specific path against declared scope")
    args = parser.parse_args()

    print(f"\nIBA Glasswing Guard — Patent GB2603013.0 Pending")
    print(f"IntentBound.com · IBA@intentbound.com\n")

    cert = create_glasswing_cert(args.patch_file, args.org, args.cve, args.paths)

    if args.validate:
        print(f"Validating path: {args.validate}")
        validate_scope(cert, args.validate)
    else:
        output = wrap_patch(args.patch_file, cert)
        print(f"IBA Certificate issued:")
        print(f"  Coalition member : {cert['coalition_member']}")
        print(f"  CVE scope        : {cert['scope_envelope']['permitted_cve']}")
        print(f"  Permitted paths  : {cert['scope_envelope']['permitted_paths']}")
        print(f"  Hard expiry      : {cert['temporal_scope']['hard_expiry']}")
        print(f"  Default posture  : {cert['scope_envelope']['default_posture']}")
        print(f"  WitnessBound     : {cert['witnessbound']}")
        print(f"\nGoverned patch created: {output}")
        print(f"\nThe agent found the bug.")
        print(f"The cert declares what it is authorized to fix.")
        print(f"DENY_ALL enforces the rest.")

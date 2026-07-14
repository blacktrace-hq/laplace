"""SEG 3 -- CI entrypoint. Runs the LAPLACE gate over a workspace, writes every
receipt as a JSON artifact, and fails the job (exit 1) if any file KILLs. Reads
the buyer ruleset from LAPLACE_CONFIG and the license from LAPLACE_LICENSE
(custom rules honoured only with a valid license). Zero network at runtime.
"""
import json
import os
import sys

from laplace_gate import oracle


def _discover(workspace):
    """Zero-assembly defaults: a buyer drops .laplace/{config.yml,license} into the
    repo and the gate just works -- no env wiring. Env still overrides."""
    cfg = os.environ.get("LAPLACE_CONFIG")
    if not cfg:
        p = os.path.join(workspace, ".laplace", "config.yml")
        cfg = p if os.path.isfile(p) else None
    lic = os.environ.get("LAPLACE_LICENSE")
    if not lic:
        p = os.path.join(workspace, ".laplace", "license")
        if os.path.isfile(p):
            lic = open(p, encoding="utf-8").read().strip()
    return cfg, lic or None


def run(workspace, out_path):
    cfg, lic = _discover(workspace)
    rules, docs, unlocked = oracle.active_rules(cfg, lic)
    receipts, blocked = [], False
    for path in oracle._collect([workspace]):
        try:
            code = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        rec = oracle.receipt(code, rules, docs)
        rec["path"] = path
        receipts.append(rec)
        if rec["verdict"] == "KILL":
            blocked = True
            print(f"KILL  {path}  receipt={rec['receipt_sha256'][:16]}")
            for cwe, why in rec["findings"]:
                print(f"  {cwe}  {why}")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"mode": "custom" if unlocked else "base", "receipts": receipts}, f, indent=2)
    kills = sum(1 for r in receipts if r["verdict"] == "KILL")
    print(f"LAPLACE: {len(receipts)} files, {kills} KILL, mode={'custom' if unlocked else 'base'}")
    print(f"receipts -> {out_path}")
    return 1 if blocked else 0


if __name__ == "__main__":
    ws = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GITHUB_WORKSPACE", ".")
    out = os.environ.get("LAPLACE_RECEIPTS", "laplace-receipts.json")
    raise SystemExit(run(ws, out))


def cli():
    ws = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GITHUB_WORKSPACE", ".")
    out = os.environ.get("LAPLACE_RECEIPTS", "laplace-receipts.json")
    raise SystemExit(run(ws, out))

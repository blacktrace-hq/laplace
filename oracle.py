"""LAPLACE oracle -- loads the sealed base pack + optional buyer rules, runs the
UNION as a zero-LLM deterministic gate, and mints the receipt.

INVARIANT: same code + same active ruleset -> identical receipt_sha256.
kill = any active rule fires. No network, no model, at runtime.
"""
import ast
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yaml  # noqa: E402
from rules.compiler import compile_rules, ruleset_hash  # noqa: E402

ENGINE_VER = "laplace-oracle-v1"
_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "base_seccode.yaml")


def _load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load(buyer_config=None):
    """Return (compiled_rules, source_docs). buyer_config is an optional path whose
    rules UNION onto the base pack -- base rules always run; buyer rules add coverage."""
    docs = [_load_yaml(_BASE)]
    if buyer_config:
        docs.append(_load_yaml(buyer_config))
    rules = []
    for d in docs:
        rules.extend(compile_rules(d))
    return rules, docs


def findings(code, rules):
    """List of (cwe, message), deduped by (cwe, message) in rule order."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [("PARSE", "unparseable - cannot certify")]
    out, seen = [], set()
    for r in rules:
        if r.fires(tree, code):
            key = (r.cwe, r.message)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def kills(code, rules):
    """Verdict: True == KILL. Mirrors the sealed oracle_seccode.kills() (len>0),
    so an unparseable file fails closed."""
    return len(findings(code, rules)) > 0


def oracle_id(docs):
    h = hashlib.sha256((ENGINE_VER + "|" + ruleset_hash(docs)).encode()).hexdigest()[:12]
    return f"{ENGINE_VER}:{h}"


def receipt(code, rules, docs):
    """The deterministic proof-of-run. Findings are sorted so the hash is
    independent of rule-evaluation order -> stable on re-run."""
    f = sorted(findings(code, rules))
    payload = {
        "engine": ENGINE_VER,
        "oracle_id": oracle_id(docs),
        "ruleset_sha256": ruleset_hash(docs),
        "input_fingerprint": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "verdict": "KILL" if f else "PASS",
        "findings": [list(x) for x in f],
    }
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["receipt_sha256"] = hashlib.sha256(canon.encode()).hexdigest()
    return payload


def _collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                if any(s in root for s in (".git", "node_modules", ".venv", "venv")):
                    continue
                files += [os.path.join(root, f) for f in fs if f.endswith(".py")]
        elif p.endswith(".py"):
            files.append(p)
    return files


def active_rules(config=None, license_token=None, public_key_hex=None, now=None):
    """Apply SEG-2 gate behaviour: buyer `config` rules are honoured ONLY with a
    valid, unexpired license; otherwise the gate runs base-pack-only (free) mode.
    `now` overrides the clock for deterministic tests. Returns (rules, docs, unlocked)."""
    unlocked = False
    if config and license_token:
        from license.verify import verify
        if verify(license_token, public_key_hex, now=now) is not None:
            unlocked = True
    rules, docs = load(config if unlocked else None)
    return rules, docs, unlocked


def main(argv):
    rules, docs, unlocked = active_rules(
        os.environ.get("LAPLACE_CONFIG"), os.environ.get("LAPLACE_LICENSE") or None
    )
    print(f"LAPLACE gate: {'custom rules unlocked' if unlocked else 'base pack (free mode)'}")
    blocked = False
    for path in _collect(argv[1:] or ["."]):
        try:
            code = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        rec = receipt(code, rules, docs)
        if rec["verdict"] == "KILL":
            blocked = True
            print(f"KILL {path}  receipt={rec['receipt_sha256'][:16]}")
            for cwe, why in rec["findings"]:
                print(f"  {cwe} -- {why}")
    if not blocked:
        print("LAPLACE gate: clean.")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

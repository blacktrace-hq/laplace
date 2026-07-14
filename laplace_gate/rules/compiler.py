"""LAPLACE rule compiler -- declarative rules -> ordered, deterministic executable
checks. Zero LLM at runtime. Unknown primitives are rejected, not skipped, so a
malformed ruleset fails loud instead of silently under-checking.

Primitives:
  call_pattern  match an ast.Call by name(s) + optional conditions (kwarg True/False,
                dynamic first arg, co-occurring / forbidden source substrings)
  source_regex  a regex over the raw source (catches what call-shape misses)
  all_of        every sub-check must fire (e.g. weak-hash AND a credential token)
"""
import ast
import hashlib
import json
import re

PRIMITIVES = ("call_pattern", "source_regex", "all_of")

# --- AST helpers, ported verbatim from the sealed oracle_seccode (parity by construction) ---
def _call_name(node):
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _kw(node, name):
    for k in node.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_true(val):
    return isinstance(val, ast.Constant) and val.value is True


def _is_false(val):
    return isinstance(val, ast.Constant) and val.value is False


def _has_dynamic_string(node):
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(arg, ast.Name):
        return True
    return False


def _flags(spec):
    return re.IGNORECASE if spec and "i" in spec else 0


# --- primitive evaluators: return True if the check fires over (tree, src) ---
def _eval_call_pattern(p, tree, src):
    if "require_src" in p and not re.search(p["require_src"], src):
        return False
    for s in p.get("forbid_src", []):
        if s in src:
            return False
    names = set(p["names"]) if "names" in p else None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if names is not None and _call_name(node) not in names:
            continue
        kt = p.get("require_kwarg_true")
        if kt and not _is_true(_kw(node, kt)):
            continue
        kf = p.get("require_kwarg_false")
        if kf and not _is_false(_kw(node, kf)):
            continue
        if p.get("require_arg0_dynamic") and not _has_dynamic_string(node):
            continue
        return True
    return False


def _eval_source_regex(p, tree, src):
    return re.search(p["pattern"], src, _flags(p.get("flags"))) is not None


def _eval_all_of(p, tree, src):
    return all(_eval_check(c, tree, src) for c in p["of"])


_EVAL = {"call_pattern": _eval_call_pattern, "source_regex": _eval_source_regex, "all_of": _eval_all_of}


def _eval_check(check, tree, src):
    t = check.get("type")
    if t not in _EVAL:
        raise ValueError(f"unknown check primitive: {t!r}")
    return _EVAL[t](check, tree, src)


class Rule:
    __slots__ = ("id", "cwe", "message", "check")

    def __init__(self, d):
        for req in ("id", "cwe", "message", "check"):
            if req not in d:
                raise ValueError(f"rule missing '{req}': {d.get('id', d)!r}")
        self.id, self.cwe, self.message, self.check = d["id"], d["cwe"], d["message"], d["check"]
        self._validate(self.check)

    def _validate(self, c):
        if not isinstance(c, dict) or c.get("type") not in PRIMITIVES:
            raise ValueError(f"rule {self.id}: unknown or missing primitive {c!r}")
        if c["type"] == "all_of":
            if not c.get("of"):
                raise ValueError(f"rule {self.id}: all_of needs a non-empty 'of'")
            for sub in c["of"]:
                self._validate(sub)

    def fires(self, tree, src):
        return _eval_check(self.check, tree, src)


def compile_rules(doc):
    """doc: {rules: [ {id,cwe,message,check}, ... ]} -> ordered list[Rule]. Order is
    preserved; rule identity is not deduped (findings dedup happens at eval)."""
    if not isinstance(doc, dict) or "rules" not in doc:
        raise ValueError("ruleset needs a top-level 'rules' list")
    return [Rule(r) for r in doc["rules"]]


def ruleset_hash(docs):
    """Stable hash over the active ruleset(s), canonical JSON -> the receipt's `ruleset` field."""
    canon = json.dumps(list(docs), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()

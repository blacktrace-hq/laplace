# LAPLACE

Deterministic, zero-LLM security gate for Python (8 CWE classes). Runs on your
machine or runner -- your code never leaves it. Reproducible receipts.

## GitHub Action
```yaml
- uses: blacktrace-hq/laplace@v1
  with:
    path: .
    license: ${{ secrets.LAPLACE_LICENSE }}
```

## pre-commit
```yaml
repos:
  - repo: https://github.com/blacktrace-hq/laplace
    rev: v1.0.0
    hooks:
      - id: laplace-gate
```

Base pack free (MIT); custom rules need a license, verified offline.
https://blacktrace.co/laplace

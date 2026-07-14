---
name: laplace-setup
description: Install and verify the LAPLACE pre-commit gate for a human who may not use terminals. Trigger when the user pastes this file, mentions LAPLACE or Blacktrace gate setup, or asks for help installing their commit gate.
version: 1.0
---

# LAPLACE Gate — Guided Setup

You are driving. The human may not code at all. Your job: get the LAPLACE
gate installed in their repository and PROVEN working — one small step per
message.

## Rules (non-negotiable)

1. One question or one command per message. Never a wall of commands.
2. After every command, ask them to paste the output before you continue.
3. Never declare success until the probe test at the bottom shows a BLOCK
   and then a PASS. "Files written" is not installed. "Installed" is not
   verified.
4. Adapt every command to their answers. Never show alternatives side by side.
5. Plain words. Name the app to open ("PowerShell — press Start, type
   powershell, Enter"), not just the shell.
6. Stuck twice on the same step → stop. Have them email x@blacktrace.co
   with the exact error text pasted in.

## What you're installing (say this once, one line)

LAPLACE checks every git commit and blocks known-dangerous code — injection,
unsafe deserialization, hardcoded credentials — before it leaves their machine.

## Their license key

{{LICENSE_KEY}}

If the line above still shows curly braces, ask the human to paste the key
from their delivery page or Blacktrace email before going further.

## Interview, in order

Ask one at a time. Skip anything their answers already settle.

1. "Windows, Mac, or Linux?" — Windows means PowerShell, never cmd.
   Mac/Linux means Terminal.
2. "Do you have a project folder you want protected, or are we testing
   fresh?" — fresh: make one (`mkdir`, `cd` into it, `git init`).
3. `git --version` — not found → install it (Windows:
   `winget install -e --id Git.Git`; Mac: `xcode-select --install`;
   Debian/Ubuntu: `sudo apt install git`). Open a NEW terminal window
   after any install.
4. `git config user.email` — empty → set `user.email` and `user.name`
   (any values), or commits fail with "tell me who you are."
5. Python — Windows: `py -0`; Mac/Linux: `python3 --version`. None →
   Windows: `winget install -e --id Python.Python.3.12`; Mac:
   `brew install python`; Debian/Ubuntu:
   `sudo apt install python3 python3-pip`. NEW terminal after.

## Write the three files (in the repo root)

Generate the write commands for THEIR shell (PowerShell here-strings on
Windows, heredocs on Mac/Linux), key inserted.

**.laplace/license** — the key above, nothing else, no trailing newline.

**.laplace/config.yml**
```yaml
version: my-rules-v1
# base 8-CWE pack always runs. add yours: blacktrace.co/laplace/build
rules: []
```

**.pre-commit-config.yaml**
```yaml
repos:
  - repo: https://github.com/blacktrace-hq/laplace
    rev: v1.1.0
    hooks:
      - id: laplace-gate
```

If `.pre-commit-config.yaml` already exists: APPEND the repo block to it.
Never overwrite theirs.

Public repository? Add `.laplace/license` to `.gitignore` and write the
file from an environment variable instead of committing the key.

## Install

Always module form — never bare `pip` or `pre-commit`. PATH and alias
breakage on real machines is the norm, not the exception.

- Windows: `py -m pip install pre-commit` then `py -m pre_commit install`
- Mac/Linux: `python3 -m pip install pre-commit && python3 -m pre_commit install`

## Prove it (mandatory — this is the whole point)

1. Have them create `laplace_probe.py` containing exactly:
   ```python
   import pickle
   pickle.loads(open("x","rb").read())
   ```
2. `git add laplace_probe.py` then `git commit -m "probe"` —
   EXPECT the commit to be BLOCKED, output naming CWE-502.
3. Delete the probe, commit again — EXPECT a pass and the commit going
   through.

Both observed → tell them, verbatim: **"LAPLACE is live. Verified — you
watched it block."**

Block missing, or pass missing → it is NOT installed. Troubleshoot below.
Do not reassure. Do not soften.

## Known failures → fixes

| they see | it means | do |
|---|---|---|
| `'sh' is not recognized` | Windows cmd, or a curl-pipe habit | use the PowerShell versions of everything |
| `pip : The term 'py -X -m pip' is not recognized` | broken pip alias in their profile | module form, always |
| `No suitable Python runtime found` | py launcher without a runtime | install Python, then a NEW terminal |
| `WARNING: The script … is not on PATH` | user-site scripts dir | ignore it; module form is immune |
| `git failed. Is it installed, and are you in a Git repository directory?` | wrong folder, or no git | `cd` to the repo root; `git init` if fresh; install git if absent |
| `Please tell me who you are` | fresh git, no identity | set `user.email` + `user.name` |
| hook runs but no laplace output | hook not registered here | re-run `py -m pre_commit install` / `python3 -m pre_commit install` in the repo root |

## First-run note

The first commit after install downloads the hook environment — a minute
or more of silence, network needed once. Silence then output is normal.

Anything the human can't answer: x@blacktrace.co.

# agy-auto-mode 🛡️

[![tests](https://github.com/marmarmamark/agy-auto-mode/actions/workflows/test.yml/badge.svg)](https://github.com/marmarmamark/agy-auto-mode/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-brightgreen.svg)](https://www.python.org/)
[![Platform: Antigravity](https://img.shields.io/badge/Antigravity-CLI%20%7C%20IDE-orange.svg)](https://github.com/google-deepmind)
[![Free Tier: 100% Free](https://img.shields.io/badge/Google%20AI%20Studio-Free%20Tier-success.svg)](https://aistudio.google.com/)

An autonomous, Claude Code-style **Auto-Mode Security Classifier** for [Google Antigravity](https://github.com/google-deepmind) (`agy` CLI and Antigravity IDE).

Stop dealing with repetitive, disruptive confirmation prompts for routine commands (`git status`, `git diff`, `git add`, `npm test`, workspace file edits) while ensuring your system is strictly protected against catastrophic actions, accidental data loss, and credential leaks.

---

## Threat Model & Scope

`agy-auto-mode` is designed to **prevent an aligned AI coding agent from executing catastrophic or dangerous actions by accident or misunderstanding** (such as recursive directory wipes, privilege escalation, force-pushing over remote history, or transmitting private credentials).

> [!NOTE]
> Developer tooling commands like `npm run <script>`, `pytest`, `cargo test`, `go test`, and `make` execute developer-defined code by construction (via `package.json`, `conftest.py`, `build.rs`, or `Makefile`). Restoring already-declared dependencies (`npm ci`, `pip install -r`) runs that same code. Auto-mode acts as an intelligent operational safety guardrail, not an operating system-level sandbox against a hostile repository or a compromised model.

---

## Key Features

- **⚡ Fast-Path Execution (<2ms):** Routine commands, inspections, builds, tests, and workspace file modifications execute instantly without calling any external API. The deterministic allow-list covers everyday development end to end — read-only utilities (`ls`, `cat`, `rg`, `jq`, `sed -n`, `find`, `awk`), read-only git (`rev-parse`, `ls-files`, `blame`, `remote -v`, `config --get`, `fetch`), build and test runners, lockfile dependency restores, pipes, `2>&1` redirection, env-prefixed and `timeout`-wrapped commands, and workspace-relative writes (`mkdir`, `touch`, `cp`, `mv`, `sed -i`, `> file`).
- **🎯 Prompts Only Where It Matters:** Because Tier 1 recognizes the routine work, confirmation is reserved for what actually carries risk. Against a 121-command corpus of everyday development commands the fast path allows 100% with no AI call; against a 55-command corpus of destructive, exfiltrating and bypass-shaped commands it allows none.
- **🔎 Substitution-Aware:** `$(...)`, backticks and `<(...)` no longer disqualify a command wholesale — the body is extracted and classified in its own right, so `cd $(git rev-parse --show-toplevel)` runs while `echo $(git checkout -- .)` still prompts.
- **🛡️ Compound Command Decomposition:** Chained commands (`;`, `&&`, `||`, `|`, `\n`) are split and analyzed so every single sub-command must be on the strict allow-list.
- **🔒 Fail-Closed By Default:** Missing schemas, unknown tools, and ambiguous offline commands default to user confirmation (`force_ask`), never silent execution.
- **⛔ Deterministic Findings Are Final:** A construct the local rules flag as dangerous always prompts. It is never handed to the AI tier, which cannot upgrade it to `allow`.
- **🌐 Metadata Blocking, Without Breaking Local Dev:** Cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`, `metadata.google.internal`) are hard-denied. Loopback and RFC1918 are *not* blocked — reaching your own dev server is routine.
- **🔄 Autonomous Cascading Failover:** If an AI model encounters rate limits (`HTTP 429`), it dynamically fails over to the next model in your pool within a global 5.5s latency budget.
- **💰 100% Free Tier Supported:** Runs on Google AI Studio's free tier with generous limits (up to 1,500 requests/day). No credit card required.

---

## Architecture

```mermaid
flowchart TD
    ToolCall[Antigravity PreToolUse Event] --> FastPath{Tier 1: Fast-Path Evaluation}
    
    FastPath -->|Catastrophic Pattern e.g. rm -rf /| Deny[Instant HARD DENY 0ms]
    FastPath -->|Cloud metadata endpoint| Deny
    FastPath -->|Dangerous Pattern e.g. sudo, git reset --hard| Ask[SOFT DENY: User Confirmation]
    FastPath -->|Sensitive Boundary e.g. ~/.ssh, /etc| Ask
    FastPath -->|Unrecognized Tool e.g. deploy_to_production| Ask
    FastPath -->|Write or redirect outside the workspace| Ask
    FastPath -->|Execution-redirecting env assignment e.g. PATH=, LD_PRELOAD=| Ask
    FastPath -->|All segments verified safe e.g. git status && git diff| Allow[Instant ALLOW <2ms]
    
    FastPath --> Segments{Per-segment verdict}
    Segments -->|dangerous e.g. git checkout -- . or source evil.sh| Ask
    Segments -->|safe| Allow
    Segments -->|unknown| AI{Tier 2: AI Auto-Classifier}
    
    AI -->|gemini-2.5-flash| Eval[Evaluate Goal & Active Policy]
    AI -->|HTTP 429 / Error| Failover1[Failover: gemini-2.5-flash-lite]
    Failover1 -->|HTTP 429 / Error| Failover2[Failover: gemini-2.0-flash / 1.5-flash]
    Failover2 -->|HTTP 429 / Error| Failover3[Failover: gemini-3.5-flash-lite / 3.1-flash-lite]
    
    Eval -->|Safe & Aligned| Allow
    Eval -->|Risky / Deviant| Ask
    Eval -->|Dangerous / Exfiltration| Deny
    
    AI -->|Timeout 5.5s / Quota Exhausted| Heuristic{Tier 3: Heuristic Fallback}
    Heuristic -->|Fail-Closed: Ambiguous Action| Ask
    Heuristic -->|Catastrophic Action| Deny
```

### Cascading Model Pool (Free Tier Quota)

| Tier | Models | Availability | Purpose |
| :--- | :--- | :--- | :--- |
| **GA Primary** | `gemini-2.5-flash`, `gemini-2.5-flash-lite` | General Availability | Fast, robust classification workhorses |
| **GA Fallback** | `gemini-2.0-flash`, `gemini-1.5-flash` | General Availability | Ultra-reliable standard backups |
| **Preview** | `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite` | Preview / Tier 1 | High-efficiency 500 RPD reserves |
| **Open Reserve** | `gemma-2-27b-it` | General Availability | High-capacity open model reserve |

*(During installation, `install.sh` automatically probes `/v1beta/models` using your API key and caches verified active models).*

---

## Quickstart

### 🤖 1-Click Install for AI Agents (Claude Code, AGY, Cursor, Aider)

Copy and paste this prompt directly into your AI assistant:

> **"Please install and configure the Antigravity Auto-Mode Security Classifier on my system:**
> 1. Clone or pull: `git clone https://github.com/marmarmamark/agy-auto-mode.git ~/.gemini/config/plugins/agy-auto-mode`
> 2. Install: `bash ~/.gemini/config/plugins/agy-auto-mode/install.sh --global --yes`
> 3. Test: `python3 ~/.gemini/config/plugins/agy-auto-mode/tests/test_classifier.py`
> 4. Check if `GEMINI_API_KEY` is in `~/.env` or environment; if missing, remind me to get a free key from https://aistudio.google.com/."**

*(See [AGENT_PROMPT.md](AGENT_PROMPT.md) for agent execution checklists).*

---

### Manual Installation

#### 1. Installation

Clone this repository directly into your global Antigravity plugins directory:

```bash
git clone https://github.com/marmarmamark/agy-auto-mode.git ~/.gemini/config/plugins/agy-auto-mode
```

Or run the included installer:

```bash
git clone https://github.com/marmarmamark/agy-auto-mode.git
cd agy-auto-mode
bash install.sh --global
```

#### 2. Configure Your Free API Key

The installer automatically checks for existing keys in your environment and prompts you:
```text
 Detected existing Gemini API key: AIzaSy...xxxx
 Use detected key? [Y/n]: 
```
- If you answer `n`, you can enter a new key which is saved to `~/.env`.
- If no key is detected, you can paste one or press Enter to run in local fail-closed heuristic mode.

You can also manually export it in your shell (`~/.zshrc` or `~/.bashrc`):
```bash
export GEMINI_API_KEY="your_api_key_here"
```
Or place it in your `~/.env` file:
```dotenv
GEMINI_API_KEY=your_api_key_here
```

Get a free Google AI Studio key at [aistudio.google.com](https://aistudio.google.com/) (free tier, no credit card required).

#### 3. Verify Installation

Run the test suite (55 tests, hermetic — no network, no API key required):

```bash
python3 ~/.gemini/config/plugins/agy-auto-mode/tests/test_classifier.py
```

---

## Customizing Security Policies

The policy rules are defined in `auto_mode_rules.json`. You can customize them globally at `~/.gemini/config/auto_mode_rules.json` (or inside the plugin directory):

```json
{
  "allow": [
    "Inspection and read-only actions: viewing files, listing directories, search, documentation lookup",
    "Read-only shell utilities: ls, cat, head, tail, wc, stat, du, df, tree, find, grep, rg, sed -n, awk, jq, sort, uniq, cut, diff, which, date",
    "Code modifications to files located strictly within trusted workspaces, including workspace-relative mkdir, touch, cp, mv, sed -i and output redirection",
    "Standard developer, build, test, and package management commands: npm, pnpm, yarn, bun, pip, python, pytest, cargo, go, tsc, make",
    "Restoring already-declared dependencies from a committed manifest or lockfile: npm ci, npm install, pip install -r, poetry install, go mod download",
    "Routine git queries and non-destructive local operations: git status, diff, log, branch, add, commit, stash, fetch, rev-parse, ls-files, blame, remote -v, config --get, and branch-shaped checkout/switch",
    "Redirecting output to /dev/null or a workspace-relative file, and descriptor duplication such as 2>&1",
    "Reading a local development server over loopback or a private subnet (plain curl fetches, no upload or file output)"
  ],
  "soft_deny": [
    "File deletions or recursive directory removals (rm, rm -rf, shred)",
    "Privileged system commands or privilege escalation (sudo, su, chown, chmod 777)",
    "Destructive git operations that discard uncommitted work or overwrite history: git push --force, git reset --hard, git clean -f, git restore, git stash drop/clear",
    "Checkout forms that discard uncommitted work: git checkout -- <path>, git checkout ., -f/--force, --discard-changes, --ours, --theirs",
    "Git flags that execute commands or write arbitrary files: --upload-pack, --receive-pack, --exec, --output, --ext-diff, and -c/--config overrides",
    "git submodule update/foreach: fetches remote content and can execute hooks",
    "Git commands that rewrite repository configuration or remotes: git config <set>, git remote add/set-url",
    "Environment assignments that redirect which binary or interpreter hook runs: PATH, LD_PRELOAD, DYLD_*, NODE_OPTIONS, PYTHONPATH, BASH_ENV, GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, IFS",
    "Installing new packages that are not already declared in the project manifest, and any global install (-g, --global)",
    "Inline interpreter code (python -c, node -e) and text-tool programs that shell out (awk system(), sed e/w/f)",
    "Sourcing arbitrary shell scripts (source/. anything other than a virtualenv activate script)",
    "Piping untrusted remote scripts directly to shell (curl | sh, wget | bash)",
    "Modifications, redirections or copies targeting sensitive system paths or any path outside workspace roots"
  ],
  "hard_deny": [
    "Data exfiltration: transferring credentials, private keys, or internal secrets to external unverified servers",
    "Requests targeting cloud instance metadata services (169.254.169.254, 169.254.170.2, metadata.google.internal)",
    "Catastrophic system destruction: wiping root filesystem, formatting disk partitions, raw device writes"
  ]
}
```

> [!NOTE]
> Rules are loaded exclusively from global configuration (`~/.gemini/config/`) to prevent untrusted cloned repositories from tampering with security boundaries.

---

## Statusline Integration

Track remaining daily requests by inspecting `~/.gemini/config/classifier_usage.json`:

```python
import json, os, time

def get_classifier_remaining():
    path = os.path.expanduser("~/.gemini/config/classifier_usage.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
                cutoff = time.time() - 86400
                timestamps = [t for t in data.get("timestamps", []) if t > cutoff]
                return max(0, data.get("daily_limit", 1500) - len(timestamps))
        except Exception:
            pass
    return 1500
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

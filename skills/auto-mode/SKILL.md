---
name: auto-mode
description: Configure and manage the autonomous permission classifier for Antigravity (agy). Use when checking auto-mode quota, adjusting allow/deny rules in auto_mode_rules.json, or troubleshooting permission prompts.
---

# Antigravity Auto-Mode Security Classifier

The `auto-mode` plugin gives Antigravity CLI (`agy`) and Antigravity IDE a
Claude Code-style **Auto-Mode Security Classifier**.

### Threat Model
Auto-mode is designed to prevent an aligned AI coding agent from executing
catastrophic or dangerous actions by accident or misunderstanding. Commands like
`npm run`, `pytest`, `cargo test`, and `make` execute developer code by design.
It is not an OS-level sandbox against a compromised model or malicious repository.

--------------------------------------------------------------------------------

## How Auto-Mode Works

Every tool call passes through a **3-Tier Decision Engine**:

1. **Tier 1: Fast Path (<2ms)**
   - Catastrophic patterns (`rm -rf /`, raw disk format, fork bombs) are instantly **denied** with 0ms latency.
   - Dangerous commands (`sudo`, `su`, `rm -rf`, `git reset --hard`, `--upload-pack`, destructive `find`) prompt for confirmation (`force_ask`).
   - Sensitive path boundaries (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`) prompt for confirmation.
   - Compound commands (chained via `;`, `&&`, `||`, `|`, `\n`) are decomposed and **each sub-command gets its own verdict** — `safe`, `dangerous`, or `unknown`.
     - Every segment `safe` → instant allow.
     - Any segment `dangerous` → `force_ask`, returned immediately. A dangerous verdict is **never** sent to Tier 2, so the AI cannot upgrade it to `allow`.
     - Otherwise → escalate to Tier 2.
   - Benign developer actions are allowed instantly, and the allow-list is broad enough that everyday work does not prompt: read-only utilities (`ls`, `cat`, `head`, `rg`, `grep`, `find`, `jq`, `awk`, `sed -n`, `wc`, `diff`, `which`, `cd`), read-only git (`status`, `diff`, `log`, `rev-parse`, `ls-files`, `blame`, `describe`, `reflog`, `remote -v`, `config --get`, `fetch`, `worktree list`), recoverable git writes (`add`, `commit`, `stash`, branch-shaped `checkout`/`switch`), build/test/lint runners, lockfile dependency restores (`npm ci`, `pip install -r`), and read-only `docker` queries.
   - Everyday shell shapes stay on the fast path too: pipes and `2>&1`, redirection to `/dev/null` or a workspace-relative file, env-prefixed commands (`NODE_ENV=test npm test`), `timeout`/`time` wrappers, virtualenv and `node_modules/.bin` launchers, and workspace-relative writes (`mkdir`, `touch`, `cp`, `mv`, `sed -i`).
   - Command substitutions (`$(...)`, backticks, `<(...)`) are extracted and classified on their own rather than blocking the fast path wholesale, so `cd $(git rev-parse --show-toplevel)` runs while `echo $(git checkout -- .)` prompts.
   - The breadth is bounded by what the segment can actually reach: a write, copy or redirect whose target leaves the workspace prompts; so do execution-redirecting env assignments (`PATH=`, `LD_PRELOAD=`, `NODE_OPTIONS=`, `PYTHONPATH=`, `BASH_ENV=`, `GIT_SSH_COMMAND=`, `IFS=`), inline interpreter code (`python -c`, `node -e`), text-tool shell escapes (`awk system()`, `sed` `e`/`w`/`-f`), and installing packages that are not already declared in the manifest.
   - Constructs that quietly destroy work or execute code are `dangerous`: `git checkout -- .` / `git checkout .` / `-f` / `--discard-changes` / `--ours` / `--theirs`, `git restore` (without `--staged`), `git stash drop|clear`, `git submodule update|foreach`, git `--upload-pack` / `--receive-pack` / `--exec` / `--output` / `--ext-diff` / `-c` overrides, destructive `find` predicates, and `source`/`.` of anything but a virtualenv activate script.
   - Safe workspace file modifications (`write_to_file`, `replace_file_content`) inside active workspaces are allowed. Edits outside workspaces or with missing targets fail closed. When the host sends no `workspacePaths`, the host-provided working directory is used as the boundary instead — the filesystem root and the bare home directory are rejected, since neither is a boundary.
   - Network tools (`read_url_content`, `browser_subagent`) hard-deny cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`, `metadata.google.internal`). Loopback and RFC1918 are **allowed** — reading your own dev server is routine. Plain `curl` fetches at a local target are fast-pathed too, unless they upload a body or write a file (`-d`, `-F`, `-T`, `-o`, `-K`, `>`).

2. **Tier 2: AI Auto-Classifier (Cascading Multi-Model Pool)**
   - Ambiguous commands or novel scripts are evaluated by Google AI Studio models using your free API key.
   - Active security policies from `auto_mode_rules.json` are serialized into the model prompt.
   - Commands are wrapped with prompt-injection defense tags `<untrusted_proposed_command>`.
   - **Cascading Failover**: If a model hits rate limits (HTTP 429), it automatically fails over without delay:
     1. `gemini-2.5-flash` (GA primary)
     2. `gemini-2.5-flash-lite` (GA fast workhorse)
     3. `gemini-2.0-flash` / `gemini-1.5-flash` (GA fallbacks)
     4. `gemini-3.5-flash-lite` / `gemini-3.1-flash-lite` (Preview workhorses)
     5. `gemini-3.8-flash` (Preview reasoning tier)
     6. `gemma-2-27b-it` (Open model reserve)
   - Runs with a strict global 5.5s timeout budget to guarantee response before Antigravity's 8.0s hook timeout.

3. **Tier 3: Fail-Closed Heuristic Fallback**
   - If offline, unauthenticated, rate-limited, or on timeout, it defaults to **fail-closed heuristics**: unrecognized or ambiguous commands prompt for confirmation (`force_ask`) rather than executing silently.

--------------------------------------------------------------------------------

## Customizing Security Policies

You can customize the rules globally in `~/.gemini/config/auto_mode_rules.json`
(or edit `auto_mode_rules.json` in the plugin directory):

```json
{
  "allow": [
    "Standard developer, build, test, and package management commands"
  ],
  "soft_deny": [
    "File deletions (rm, rm -rf)",
    "Privileged system commands (sudo, su)",
    "Force git pushes or hard resets"
  ],
  "hard_deny": [
    "Data exfiltration of credentials, private keys, or API tokens",
    "Root filesystem wipes or disk partition formatting"
  ]
}
```

> [!NOTE]
> Rules are loaded exclusively from global configuration to prevent untrusted cloned repositories from tampering with security boundaries.

--------------------------------------------------------------------------------

## Managing API Keys

The classifier checks for your Google AI Studio API key in:
1. Shell environment: `export GEMINI_API_KEY="your-key-here"`
2. Shell environment: `export GOOGLE_API_KEY="your-key-here"`
3. User env file: `~/.env` or `~/.gemini/config/.env`

Get a free key (no credit card required) at [Google AI Studio](https://aistudio.google.com/).

--------------------------------------------------------------------------------

## Monitoring Usage

Check current rolling 24-hour quota usage:
```bash
cat ~/.gemini/config/classifier_usage.json
```

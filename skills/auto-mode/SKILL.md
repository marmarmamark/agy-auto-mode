---
name: auto-mode
description: Configure and manage the autonomous permission classifier for Antigravity (agy). Use when checking auto-mode quota, adjusting allow/deny rules in auto_mode_rules.json, or troubleshooting permission prompts.
---

# Antigravity Auto-Mode Security Classifier

The `auto-mode` plugin gives Antigravity CLI (`agy`) and Antigravity IDE a
Claude Code-style **Auto-Mode Security Classifier**. It prevents repetitive,
disruptive confirmation prompts for benign developer commands while strictly
safeguarding your machine against destructive actions or secret leaks.

--------------------------------------------------------------------------------

## How Auto-Mode Works

Every tool call passes through a **3-Tier Decision Engine**:

1. **Tier 1: Fast Path (<2ms)**
   - All read/inspection tools (`view_file`, `list_dir`, `grep_search`) are instantly allowed.
   - File edits (`write_to_file`, `replace_file_content`) inside your active workspace are instantly allowed.
   - Benign developer commands (`git status`, `git diff`, `npm test`, `cargo check`, etc.) are instantly allowed.
   - Catastrophic actions (e.g., `rm -rf /`, formatting disk devices) are instantly **denied** with 0ms latency.

2. **Tier 2: AI Auto-Classifier (Cascading Multi-Model Pool)**
   - Ambiguous commands or novel scripts are evaluated by Google AI Studio models using your free API key.
   - Evaluates commands against your stated user objective and policy rules.
   - **Cascading Failover**: If a model hits quota limits (HTTP 429), it automatically fails over without delay:
     1. `gemini-3.5-flash-lite` (500 requests/day, 15 RPM)
     2. `gemini-3.1-flash-lite` (500 requests/day, 15 RPM)
     3. `gemini-3.5-flash` / `gemini-3.7-flash` / `gemini-3.8-flash` / `gemini-2.5-flash` (20 RPD frontier pool)
     4. `gemma-4-31b-it` / `gemma-4-26b-a4b-it` (14,400 RPD open model reserve)

3. **Tier 3: Graceful Heuristic Fallback**
   - If offline, unauthenticated, or on network timeout, it defaults to deterministic local heuristics.

--------------------------------------------------------------------------------

## Customizing Security Policies

You can customize the rules by modifying `auto_mode_rules.json` either globally in
`~/.gemini/config/auto_mode_rules.json` or per-project in `.agents/auto_mode_rules.json`:

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

--------------------------------------------------------------------------------

## Managing API Keys

The classifier checks for your Google AI Studio API key in:
1. Environment variable: `export GEMINI_API_KEY="your-key-here"`
2. Environment variable: `export GOOGLE_API_KEY="your-key-here"`
3. `.env` file in your workspace or `~/.env`

Get a free key with no credit card required at: [Google AI Studio](https://aistudio.google.com/).

--------------------------------------------------------------------------------

## Monitoring Usage

Check current rolling 24-hour quota usage:
```bash
cat ~/.gemini/config/classifier_usage.json
```

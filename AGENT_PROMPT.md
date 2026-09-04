# Agent Onboarding & Installation Guide

This file contains copy-paste prompts and automated instructions tailored for AI coding assistants (such as **Antigravity**, **Claude Code**, **Cursor**, **Aider**, or **Hermes**) to autonomously clone, install, verify, and configure `agy-auto-mode` on your machine.

---

## 📋 Copy-Paste Prompt for Your AI Agent

Copy and paste the prompt below directly into your AI assistant chat:

```text
Please install and verify the Antigravity Auto-Mode Security Classifier plugin on my system:

1. Clone or pull the repository:
   git clone https://github.com/marmarmamark/agy-auto-mode.git ~/.gemini/config/plugins/agy-auto-mode

2. Run the non-interactive automated installer:
   bash ~/.gemini/config/plugins/agy-auto-mode/install.sh --global --yes

3. Verify the installation by running the test suite:
   python3 ~/.gemini/config/plugins/agy-auto-mode/tests/test_classifier.py

4. Check if a Google AI Studio API key (GEMINI_API_KEY or GOOGLE_API_KEY) is configured in my environment or ~/.env. If missing, remind me that I can grab a free key with no credit card at https://aistudio.google.com/ and add it to ~/.env to unlock Tier-2 AI classification.
```

---

## 🤖 Agent Execution Checklist

If you are an AI assistant executing this installation:

- [ ] **Step 1: Check Pre-requisites**
  Verify Python 3 is installed (`python3 --version`). Ensure `~/.gemini/config/plugins` exists or can be created.
- [ ] **Step 2: Deploy Plugin**
  Target directory: `~/.gemini/config/plugins/agy-auto-mode`
  If already cloned, run `git -C ~/.gemini/config/plugins/agy-auto-mode pull`.
- [ ] **Step 3: Execute Installer**
  Run `bash ~/.gemini/config/plugins/agy-auto-mode/install.sh --global --yes`.
  The `--yes` flag ensures non-interactive execution without waiting on stdin.
- [ ] **Step 4: Run Health Check**
  Run `python3 ~/.gemini/config/plugins/agy-auto-mode/tests/test_classifier.py`.
  All 9 tests must pass.
- [ ] **Step 5: API Key Audit**
  Inspect if `GEMINI_API_KEY` or `GOOGLE_API_KEY` is present in `os.environ` or `~/.env`.
  - If present: Report that Tier-2 AI classification and multi-model failover are active.
  - If missing: Clarify that Tier-1 Fast-Path (<2ms) and Tier-3 Heuristics are already working, and provide the user with the link to grab their free key.

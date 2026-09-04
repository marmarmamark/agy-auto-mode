#!/usr/bin/env python3
"""
Antigravity Claude Code-Style Auto Mode Classifier
--------------------------------------------------
PreToolUse lifecycle hook implementing an autonomous AI-driven security
classifier inspired by Claude Code's auto-mode.

Architecture:
  - Tier 1 (Fast Path): <2ms instant allowance for read tools, workspace edits,
    and standard benign developer commands without invoking any external API.
  - Tier 2 (AI Auto-Classifier): Evaluates ambiguous, multi-step, or risky commands
    against auto_mode_rules.json and conversation intent using free-tier Google AI
    Studio models with automatic cascading failover across model pools.
  - Tier 3 (Graceful Fallback): Seamless fallback to deterministic safety heuristics
    if offline, unauthenticated, rate-limited (HTTP 429), or on timeout.
"""

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration & Model Pool
# ---------------------------------------------------------------------------

DAILY_LIMIT = 15000  # Multi-model pool including Gemma high-capacity reserves
MODEL_POOL = [
    "gemini-3.5-flash-lite",  # 500 RPD, 15 RPM (Primary fast & smart workhorse)
    "gemini-3.1-flash-lite",  # 500 RPD, 15 RPM (Secondary fast-path workhorse)
    "gemini-3.5-flash",       # 20 RPD (Frontier reserve)
    "gemini-3.7-flash",       # 20 RPD (Frontier reserve)
    "gemini-3.8-flash",       # 20 RPD (Frontier reserve)
    "gemini-2.5-flash",       # 20 RPD (Frontier reserve)
    "gemma-4-31b-it",         # 14,400 RPD (High-capacity open reserve)
    "gemma-4-26b-a4b-it",     # 14,400 RPD (High-capacity open reserve)
]
API_TIMEOUT = 4.0  # seconds per model attempt

USAGE_FILE = os.path.expanduser("~/.gemini/config/classifier_usage.json")

# Safe read / inspection tools (instant allow)
SAFE_READ_TOOLS = {
    "view_file",
    "list_dir",
    "grep_search",
    "read_resource",
    "list_resources",
    "read_url_content",
    "read_browser_page",
    "manage_task",
    "schedule",
    "ask_question",
    "generate_image",
    "browser_subagent",
}

# File modification tools
FILE_EDIT_TOOLS = {
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
}

# Instant fast-path safe command prefixes (<1ms, no LLM required)
FAST_PATH_SAFE_COMMAND_PREFIXES = (
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git show",
    "git stash list",
    "git tag",
    "ls",
    "pwd",
    "which",
    "cat ",
    "head ",
    "tail ",
    "grep ",
    "echo ",
    "find ",
    "wc ",
    "pytest",
    "npm test",
    "npm run ",
    "cargo check",
    "cargo test",
    "go test",
    "pnpm test",
    "yarn test",
    "vitest",
    "python3 -m unittest",
    "tsc --noEmit",
)

# Catastrophic patterns: Hard deny immediately (0ms)
CATASTROPHIC_PATTERNS = [
    (r"\brm\s+-(?:r[fF]|f[rR])\s+(?:/\s*$|/\*|/\s+)", "Root filesystem wipe"),
    (r"\bmkfs(?:\.[a-z0-9]+)?\s+", "Raw disk filesystem formatting"),
    (r"\bdd\s+.*if=.*of=/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+)", "Raw disk partition overwrite"),
    (r">\s*/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+)", "Direct partition write redirection"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb denial of service"),
    (r"\b(?:curl|wget)\b.*(?:\.ssh/|\.aws/|\.env\b|\.gnupg/)", "Credential/key exfiltration attempt"),
]

# Obvious dangerous patterns: Require user confirmation (soft deny)
OBVIOUS_DANGEROUS_PATTERNS = [
    (r"\bsudo\b", "Privileged execution (sudo)"),
    (r"\bsu\b", "Switch user execution (su)"),
    (r"\bchown\b", "Ownership modification"),
    (r"\bchmod\s+(?:-R\s+)?(?:777|a\+[rwx]+)\b", "Permissive permission change"),
    (r"\brm\s+-[a-zA-Z]*r", "Recursive deletion"),
    (r"\brm\s+-[a-zA-Z]*f", "Forced file deletion"),
    (r"\bshred\b", "Secure file shredding"),
    (r"\bgit\s+push\s+.*--(?:force|f)\b", "Forced git push"),
    (r"\bgit\s+reset\s+--hard\b", "Hard git reset discarding changes"),
    (r"\bgit\s+clean\s+-[a-zA-Z]*f\b", "Git clean discarding untracked files"),
    (r"\bgit\s+branch\s+-D\b", "Force branch deletion"),
    (r"(?:curl|wget)\b.*\|\s*(?:ba|z)?sh\b", "Untrusted script piped directly to shell"),
    (r"\bnpm\s+publish\b", "NPM package publish"),
    (r"\bpip\s+install\s+.*--break-system-packages", "System package override"),
]

# Sensitive paths requiring explicit prompt
SENSITIVE_PATHS = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "/etc",
    "/System",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/Library",
]

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def record_classifier_api_call():
    """Track daily API usage using a rolling 24-hour sliding window."""
    now = time.time()
    cutoff = now - 86400
    history = []
    if os.path.exists(USAGE_FILE):
        try:
            with open(USAGE_FILE, "r") as f:
                data = json.load(f)
                history = data.get("timestamps", [])
        except Exception:
            history = []

    history = [t for t in history if isinstance(t, (int, float)) and t > cutoff]
    history.append(now)

    usage = {
        "daily_limit": DAILY_LIMIT,
        "used_24h": len(history),
        "remaining": max(0, DAILY_LIMIT - len(history)),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "timestamps": history
    }
    try:
        os.makedirs(os.path.dirname(USAGE_FILE), exist_ok=True)
        tmp_file = USAGE_FILE + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(usage, f, indent=2)
        os.replace(tmp_file, USAGE_FILE)
    except Exception:
        pass

def load_gemini_api_key(workspace_paths=None):
    """Retrieve Google AI Studio API key from environment variables or .env files."""
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        val = os.environ.get(var)
        if val and val.strip():
            return val.strip()

    candidate_files = []
    if workspace_paths:
        for ws in workspace_paths:
            candidate_files.append(os.path.join(ws, ".env"))

    candidate_files.extend([
        os.path.expanduser("~/.env"),
        os.path.expanduser("~/.gemini/config/.env"),
        os.path.join(os.path.dirname(__file__), "..", ".env")
    ])

    for env_file in candidate_files:
        if os.path.exists(env_file):
            try:
                with open(env_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k in ("GEMINI_API_KEY", "GOOGLE_API_KEY") and v:
                            return v
            except Exception:
                pass

    return None

def load_auto_mode_rules(workspace_paths=None):
    """Locate and load auto_mode_rules.json with fallback to default policies."""
    candidate_paths = []
    if workspace_paths:
        for ws in workspace_paths:
            candidate_paths.append(os.path.join(ws, ".agents", "auto_mode_rules.json"))
            candidate_paths.append(os.path.join(ws, "auto_mode_rules.json"))

    candidate_paths.extend([
        os.path.join(os.path.dirname(__file__), "..", "auto_mode_rules.json"),
        os.path.expanduser("~/.gemini/config/auto_mode_rules.json"),
    ])

    for path in candidate_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception:
                pass

    return {
        "allow": ["Routine developer tools, builds, unit tests, and workspace file modifications."],
        "soft_deny": ["File deletions, privilege escalation, and sensitive system modifications."],
        "hard_deny": ["Credential exfiltration, root wipes, and disk formatting."]
    }

def is_path_sensitive(path):
    """Check if target path intersects protected or sensitive locations."""
    if not path:
        return False
    clean = os.path.expanduser(path.strip())
    for sp in SENSITIVE_PATHS:
        expanded = os.path.expanduser(sp)
        if clean == expanded or clean.startswith(expanded + os.sep):
            return True
    return False

def is_path_in_workspaces(path, workspaces):
    """Ensure path is contained within at least one active workspace directory."""
    if not path or not workspaces:
        return True
    clean = os.path.abspath(os.path.expanduser(path.strip()))
    for ws in workspaces:
        clean_ws = os.path.abspath(os.path.expanduser(ws.strip()))
        if clean == clean_ws or clean.startswith(clean_ws + os.sep):
            return True
    return False

def extract_user_intent_from_transcript(transcript_path):
    """Extract recent user goal from session transcript for context-aware classification."""
    if not transcript_path or not os.path.exists(transcript_path):
        return None
    try:
        user_messages = []
        with open(transcript_path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    step = json.loads(line)
                    if step.get("type") == "USER_INPUT" and step.get("content"):
                        user_messages.append(step["content"].strip())
                except Exception:
                    continue
        if user_messages:
            return user_messages[-1][:400]
    except Exception:
        pass
    return None

def extract_json_decision(raw_text):
    """Extract decision JSON from raw output or markdown code blocks."""
    if not raw_text:
        return None
    raw = raw_text.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    s = raw.find("{")
    e = raw.rfind("}")
    if s != -1 and e != -1 and e > s:
        try:
            return json.loads(raw[s:e+1])
        except Exception:
            pass
    return None

# ---------------------------------------------------------------------------
# Core Classification Tiers
# ---------------------------------------------------------------------------

def fallback_heuristic_check(cmd_line):
    """Tier 3: Deterministic safety heuristics if AI is offline or exhausted."""
    clean_cmd = cmd_line.strip()
    for pattern, desc in CATASTROPHIC_PATTERNS:
        if re.search(pattern, clean_cmd, re.IGNORECASE):
            return {"decision": "deny", "reason": f"Hard Deny: {desc}"}

    for pattern, desc in OBVIOUS_DANGEROUS_PATTERNS:
        if re.search(pattern, clean_cmd, re.IGNORECASE):
            return {"decision": "force_ask", "reason": f"Soft Deny: {desc} in '{clean_cmd[:50]}'"}

    for sp in SENSITIVE_PATHS:
        if sp in clean_cmd:
            return {"decision": "force_ask", "reason": f"Soft Deny: References sensitive path: {sp}"}

    return {"decision": "allow", "reason": "Tier-3 Fallback: Permitted safe dev action"}

def call_gemini_auto_classifier(api_key, user_intent, cmd_line, rules):
    """Tier 2: AI auto-classifier with cascading multi-model pool failover."""
    system_instruction = (
        "You are an autonomous Auto-Mode Security Classifier for an AI pair programmer (similar to Claude Code's auto-mode).\n"
        "Your task: evaluate whether a proposed command is safe, aligned with the user objective, or dangerous according to the policy.\n\n"
        "Policy rules:\n"
        "- ALLOW: Safe development, builds, tests, non-destructive file operations, git queries, package management aligned with the user objective.\n"
        "- SOFT_DENY (ask): Destructive actions, file deletions, dangerous git commands (force push/reset hard), sudo, external modifications.\n"
        "- HARD_DENY (deny): Data exfiltration of secrets/keys, root wipes, disk formats.\n\n"
        "Respond ONLY with valid JSON in this exact structure:\n"
        "{\"decision\": \"allow\" | \"ask\" | \"deny\", \"reason\": \"<concise explanation>\"}"
    )

    prompt = (
        f"User Objective: {user_intent or 'General development session'}\n"
        f"Proposed Command: {cmd_line}\n"
        f"Classify this command now."
    )

    for model_name in MODEL_POOL:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

        if model_name.startswith("gemma"):
            combined_text = f"{system_instruction}\n\nTask:\n{prompt}"
            payload = {
                "contents": [{"parts": [{"text": combined_text}]}],
                "generationConfig": {"temperature": 0.0}
            }
        else:
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "generationConfig": {
                    "temperature": 0.0,
                    "responseMimeType": "application/json"
                }
            }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                record_classifier_api_call()
                raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                parsed = extract_json_decision(raw_text)
                if not parsed:
                    continue
                dec = str(parsed.get("decision", "ask")).lower()
                reason = str(parsed.get("reason", "Evaluated by AI Auto-Classifier"))
                if dec == "allow":
                    return {"decision": "allow", "reason": f"AI Auto-Mode ({model_name}): {reason}"}
                elif dec == "deny":
                    return {"decision": "deny", "reason": f"AI Auto-Mode Hard Deny ({model_name}): {reason}"}
                else:
                    return {"decision": "force_ask", "reason": f"AI Auto-Mode Soft Deny ({model_name}): {reason}"}
        except urllib.error.HTTPError as e:
            if e.code in (429, 503, 500, 404):
                continue
            continue
        except Exception:
            continue

    return None

def classify(payload):
    tool_call = payload.get("toolCall") or {}
    tool_name = tool_call.get("name") or ""
    tool_args = tool_call.get("args") or {}
    workspaces = payload.get("workspacePaths") or []
    transcript_path = payload.get("transcriptPath") or ""

    # Tier 1: Safe read/inspection tools -> Instant allow (<1ms)
    if tool_name in SAFE_READ_TOOLS or tool_name.startswith("read_") or tool_name.startswith("list_"):
        return {"decision": "allow", "reason": f"Fast-Path: Safe tool '{tool_name}' allowed"}

    # Tier 1: File edits -> Verify workspace boundary
    if tool_name in FILE_EDIT_TOOLS:
        target_file = tool_args.get("TargetFile") or tool_args.get("path")
        if not target_file:
            return {"decision": "allow", "reason": "Fast-Path: Empty target file"}
        if is_path_sensitive(target_file):
            return {"decision": "force_ask", "reason": f"Soft Deny: Target file in sensitive path: {target_file}"}
        if workspaces and not is_path_in_workspaces(target_file, workspaces):
            return {"decision": "force_ask", "reason": f"Soft Deny: Target file outside workspace: {target_file}"}
        return {"decision": "allow", "reason": "Fast-Path: Workspace file edit allowed"}

    # Terminal command classification
    if tool_name == "run_command":
        cmd_line = (tool_args.get("CommandLine") or "").strip()
        if not cmd_line:
            return {"decision": "allow", "reason": "Fast-Path: Empty command"}

        # Instant catastrophic checks
        for pattern, desc in CATASTROPHIC_PATTERNS:
            if re.search(pattern, cmd_line, re.IGNORECASE):
                return {"decision": "deny", "reason": f"Hard Deny: {desc}"}

        # Fast-path benign prefixes
        for prefix in FAST_PATH_SAFE_COMMAND_PREFIXES:
            if cmd_line.startswith(prefix):
                return {"decision": "allow", "reason": f"Fast-Path: Routine command '{prefix}' allowed"}

        # Obvious dangerous patterns before API invocation
        for pattern, desc in OBVIOUS_DANGEROUS_PATTERNS:
            if re.search(pattern, cmd_line, re.IGNORECASE):
                return {"decision": "force_ask", "reason": f"Soft Deny: {desc} in '{cmd_line[:50]}'"}

        # Tier 2: AI Auto-Classifier query
        api_key = load_gemini_api_key(workspaces)
        if api_key:
            user_intent = extract_user_intent_from_transcript(transcript_path)
            rules = load_auto_mode_rules(workspaces)
            ai_decision = call_gemini_auto_classifier(api_key, user_intent, cmd_line, rules)
            if ai_decision:
                return ai_decision

        # Tier 3: Deterministic heuristic fallback
        return fallback_heuristic_check(cmd_line)

    return {"decision": "allow", "reason": f"Tool '{tool_name}' allowed"}

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input or not raw_input.strip():
            result = {"decision": "allow", "reason": "No payload"}
        else:
            payload = json.loads(raw_input)
            result = classify(payload)
    except Exception as e:
        result = {"decision": "force_ask", "reason": f"Classifier exception: {str(e)}"}

    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()

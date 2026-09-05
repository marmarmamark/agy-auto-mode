#!/usr/bin/env bash
#
# Antigravity Auto-Mode Plugin Installer
# -------------------------------------
# Installs agy-auto-mode into your Antigravity configuration.
#
# Usage:
#   # Install globally (recommended, applies to all workspaces):
#   bash install.sh --global
#
#   # Install into current workspace:
#   bash install.sh --workspace
#
set -euo pipefail

TARGET_MODE="--global"
AUTO_CONFIRM=false

for arg in "$@"; do
  case "${arg}" in
    --workspace)
      TARGET_MODE="--workspace"
      ;;
    --global)
      TARGET_MODE="--global"
      ;;
    -y|--yes|--non-interactive|--agent)
      AUTO_CONFIRM=true
      ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Antigravity Auto-Mode Installer"

# Check Python 3
if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required but not found in PATH." >&2
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "==> Detected Python: ${PYTHON_VERSION}"

if [ "${TARGET_MODE}" = "--workspace" ]; then
  DEST_DIR="${PWD}/.agents/plugins/agy-auto-mode"
  echo "==> Installing into workspace: ${DEST_DIR}"
else
  DEST_DIR="${HOME}/.gemini/config/plugins/agy-auto-mode"
  echo "==> Installing globally: ${DEST_DIR}"
fi

mkdir -p "${DEST_DIR}"
mkdir -p "${DEST_DIR}/scripts"
mkdir -p "${DEST_DIR}/rules"
mkdir -p "${DEST_DIR}/skills/auto-mode"

cp "${REPO_DIR}/plugin.json" "${DEST_DIR}/"
cat <<EOF > "${DEST_DIR}/hooks.json"
{
  "agy-auto-mode": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${DEST_DIR}/scripts/permission_classifier.py",
            "timeout": 8
          }
        ]
      }
    ]
  }
}
EOF
cp "${REPO_DIR}/auto_mode_rules.json" "${DEST_DIR}/"
cp "${REPO_DIR}/scripts/permission_classifier.py" "${DEST_DIR}/scripts/"
chmod +x "${DEST_DIR}/scripts/permission_classifier.py"
cp "${REPO_DIR}/rules/AGENTS.md" "${DEST_DIR}/rules/"
cp "${REPO_DIR}/skills/auto-mode/SKILL.md" "${DEST_DIR}/skills/auto-mode/"

# Check API Key configuration
API_KEY="${GEMINI_API_KEY:-${GOOGLE_API_KEY:-}}"
ENV_FILE="${HOME}/.env"

if [ -z "${API_KEY}" ] && [ -f "${ENV_FILE}" ]; then
  API_KEY=$(grep -E '^(GEMINI_API_KEY|GOOGLE_API_KEY)=' "${ENV_FILE}" 2>/dev/null | head -n 1 | cut -d '=' -f2- | tr -d '"' | tr -d "'" || true)
fi

# Helper to safely persist API key in ~/.env
save_key() {
  local new_key="$1"
  touch "${ENV_FILE}"
  TARGET_ENV="${ENV_FILE}" KEY_VAL="${new_key}" python3 -c '
import os
path = os.path.expanduser(os.environ["TARGET_ENV"])
key_val = os.environ["KEY_VAL"]
lines = []
if os.path.exists(path):
    with open(path, "r") as f:
        lines = f.readlines()
new_lines = []
replaced = False
for line in lines:
    if line.strip().startswith("GEMINI_API_KEY="):
        new_lines.append(f"GEMINI_API_KEY=\"{key_val}\"\n")
        replaced = True
    else:
        new_lines.append(line)
if not replaced:
    new_lines.append(f"GEMINI_API_KEY=\"{key_val}\"\n")
with open(path, "w") as f:
    f.writelines(new_lines)
'
  echo "==> Saved GEMINI_API_KEY to ${ENV_FILE}"
}

if [ -t 0 ] && [ "${AUTO_CONFIRM}" = false ]; then
  echo ""
  echo "------------------------------------------------------------------"
  echo " Google AI Studio Key Setup (Free Tier: 500+ requests/day)"
  echo " Get a free key with no credit card: https://aistudio.google.com/"
  echo "------------------------------------------------------------------"
  if [ -n "${API_KEY}" ]; then
    MASKED_KEY="${API_KEY:0:6}...${API_KEY: -4}"
    echo " Detected existing Gemini API key: ${MASKED_KEY}"
    read -r -p " Use detected key? [Y/n]: " USE_DETECTED
    USE_DETECTED="${USE_DETECTED:-y}"
    if [[ "${USE_DETECTED}" =~ ^[Nn] ]]; then
      read -r -p " Enter new Gemini API key: " NEW_KEY
      if [ -n "${NEW_KEY}" ]; then
        save_key "${NEW_KEY}"
        API_KEY="${NEW_KEY}"
      else
        echo "==> Keeping existing key."
      fi
    else
      echo "==> Using existing API key."
    fi
  else
    read -r -p " Paste your Gemini API key (or press Enter to skip): " USER_KEY
    if [ -n "${USER_KEY}" ]; then
      save_key "${USER_KEY}"
      API_KEY="${USER_KEY}"
    else
      echo "==> Skipping API key setup (classifier will run in local heuristic mode)."
    fi
  fi
fi

# Probe and cache active models if API key is present
if [ -n "${API_KEY:-}" ]; then
  echo "==> Probing available Gemini models for your API key..."
  PROBE_KEY="${API_KEY}" python3 -c '
import urllib.request, json, os, sys

api_key = os.environ.get("PROBE_KEY", "").strip()
if not api_key:
    sys.exit(0)
url = "https://generativelanguage.googleapis.com/v1beta/models"
req = urllib.request.Request(url, headers={"x-goog-api-key": api_key})
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        available = {m["name"].replace("models/", "") for m in data.get("models", [])}
        preferred = [
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-3.5-flash-lite",
            "gemini-3.1-flash-lite",
            "gemini-3.8-flash",
            "gemma-2-27b-it",
        ]
        active = [m for m in preferred if m in available]
        if active:
            out_file = os.path.expanduser("~/.gemini/config/verified_classifier_models.json")
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            with open(out_file, "w") as f:
                json.dump({"models": active}, f, indent=2)
            print("==> Verified active models on your account:", ", ".join(active[:4]))
except Exception:
    pass
' || true
fi

# Verify hook execution
echo "==> Testing hook execution..."
TEST_PAYLOAD='{"toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}, "workspacePaths": ["'"${PWD}"'"]}'
OUTPUT=$(echo "${TEST_PAYLOAD}" | python3 "${DEST_DIR}/scripts/permission_classifier.py")

if echo "${OUTPUT}" | grep -q '"decision": "allow"'; then
  echo "==> Fast-path hook test passed: ${OUTPUT}"
else
  echo "Warning: Hook returned unexpected response: ${OUTPUT}"
fi

echo ""
echo "=================================================================="
echo " Antigravity Auto-Mode is installed and active!"
echo "=================================================================="
echo " How it works:"
echo " 1. Antigravity automatically invokes this hook before every tool call."
echo " 2. Safe actions (<2ms) and workspace edits run automatically without prompts."
echo " 3. Risky commands (rm -rf, sudo, force push) prompt you for confirmation."
echo " 4. Ambiguous commands are classified by Gemini Flash Lite using your free key."
echo "=================================================================="

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dependency installs run on the fast path (`npm install <pkg>`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `poetry add`, `cargo add`, `go get`). Global installs (`-g`, `--global`, `--break-system-packages`) and remote or VCS sources (`git+`, a URL) still prompt.
- Inline interpreter one-liners (`python3 -c`, `node -e`) run on the fast path when the program text stays clear of the shell, the network, the environment, and the filesystem. Aliased escapes are matched on the call shape, so `import os as o; o.system(...)` is caught where a module-name match would miss it.
- `rm -rf` of build artifacts (`node_modules`, `dist`, `build`, `out`, `target`, `coverage`, `__pycache__`, `.cache`, `.next`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `.gradle`) inside the workspace, and reads/writes/removals under a genuine `/tmp`.
- Plain `curl` GETs to any host, not only loopback and RFC1918. Uploads (`-d`, `-F`, `-T`), file output (`-o`, `-O`, `-K`), non-GET methods, and `curl | sh` still prompt or deny.
- `git pull` and `git merge` on the fast path, alongside the existing `git fetch`.

### Fixed
- Installer model probe verifies reachability by making one minimal `generateContent` call per candidate, instead of trusting the `supportedGenerationMethods` field in the model listing. `gemini-2.5-flash` and `gemini-2.5-flash-lite` advertise that method and still return HTTP 404 when called, so the previous probe cached two dead models at the head of the pool. The runtime demoted them on first use, but every re-run of `install.sh` put them back, costing two wasted round-trips on the next ambiguous command.
- **Security: the `/tmp` exemption was a textual lookahead, so `rm -rf /tmp/../etc` read as a `/tmp` path and was allowed outright.** Operands are now resolved with `realpath` before they are judged.
- **Security: the recursive-deletion pattern never matched the form people actually type.** `\brm\s+-[a-zA-Z]*r\b` required the flag cluster to end in `r`, so `rm -fr x` matched and `rm -rf x` did not, and the companion `rm -...f` rule had been deleted. `rm` is now owned entirely by the segment classifier, which resolves paths instead of pattern-matching them.
- Command segmentation is quote-aware. A `;` or `|` inside a quoted string was treated as a separator, shredding `python3 -c 'import json; print(x)'` into nonsense segments that then failed closed. An unterminated quote falls back to the previous naive split, which over-segments and so can only prompt more, never less.
- Write commands with mixed operands (`mv src /tmp/stash`) are judged per operand instead of requiring every operand to satisfy the same rule, which previously meant a workspace/temp pair satisfied neither.

## [1.1.0] - 2026-09-05

### Added
- Three-state segment verdicts (safe / dangerous / unknown). A segment judged dangerous returns force_ask immediately and is never sent to the AI tier, which cannot upgrade it to allow.
- Broader Tier 1 fast path so routine work stops prompting: read-only utilities (ls, cat, head, rg, grep, find, jq, awk, wc, diff, which, command -v), read-only git (status, diff, log, rev-parse, ls-files, blame, describe, reflog), build/test/lint runners (go run, go vet, gofmt, npm view, pnpm run, yarn run, bun run, jest, vitest, mocha, prettier, black, isort, mypy, flake8), lockfile restores (npm ci, pip install -r), and read-only docker queries.
- Command substitutions are extracted and classified on their own instead of blocking the fast path wholesale, so `cd $(git rev-parse --show-toplevel)` runs while `echo $(git checkout -- .)` prompts.
- CI workflow running the test suite on Python 3.8 and 3.12.

### Changed
- Cloud metadata endpoints (169.254.169.254, 169.254.170.2, metadata.google.internal) are hard-denied, but loopback and RFC1918 are no longer blocked. Reaching a local dev server is routine. Plain curl fetches at a local target are fast-pathed unless they upload a body or write a file.
- Tier 3 fallback is fail-closed: unrecognized commands prompt rather than execute.
- Model pool leads with GA models; install.sh probes /v1beta/models and caches the ones the API key can actually reach.
- auto_mode_rules.json, README and SKILL.md now describe actual behaviour.

### Fixed
- Compound commands are decomposed on ; && || | and newline, and every segment must be safe. Previously `git status; rm -rf ~/Documents` was allowed because only the prefix was matched.
- Bare credential filenames are detected. The path patterns were anchored, so `cat .env` was allowed.
- `source` and `.` of arbitrary scripts no longer fast-pathed; only virtualenv activate scripts are.
- Checkout forms that discard uncommitted work now prompt: git checkout -- ., git checkout ., -f, --force, --discard-changes, --ours, --theirs. Also git submodule update and foreach.
- Git flags that execute commands or write arbitrary files are blocked: --upload-pack, --receive-pack, --exec, --output, --ext-diff, and -c config overrides.
- Sensitive path matching uses path boundaries, so .venv/bin and /usr/local/bin no longer false-positive.
- Fail-closed defaults for unknown tools, missing target file, empty payload and empty command.
- `2>&1` was split on `&` into nonsense segments; any `>` disqualified a segment.
- Tier 2 latency is bounded by a global deadline below the 8s hook timeout; the API key is sent as a header rather than in the query string; the daily quota is enforced.

### Security
- Prompt-injection defence: the proposed command is fenced in untrusted_proposed_command tags and the model is told to treat it as data.
- auto_mode_rules.json is loaded only from trusted global locations, so a cloned repository cannot supply its own security policy.

## [1.0.0] - 2026-09-05

### Added
- Initial release: three-tier PreToolUse permission classifier for Antigravity (agy) with fast-path allow-listing, a Google AI Studio classifier tier with cascading model failover, and a deterministic heuristic fallback.
- Plugin packaging: hooks.json, SKILL.md, AGENTS.md rules, install.sh, and a 1-click agent onboarding prompt.

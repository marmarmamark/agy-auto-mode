# Auto-Mode Security Guidelines

You are operating with the **Auto-Mode Security Classifier** active.

## Operating Principles
1. **Stay Within Workspace Boundaries**: Keep all file writes, edits, and scratch files strictly within the active workspace paths. Modifications targeting paths outside the workspace or sensitive system directories (`~/.ssh`, `~/.aws`, `/etc`) will trigger an explicit user confirmation prompt.
2. **Avoid Destructive Actions**: Never use destructive flags (`rm -rf`, `git reset --hard`, `git push --force`) unless explicitly requested by the user.
3. **Prefer Safe, Non-Destructive Commands**: Use standard dev commands (`npm test`, `cargo check`, `git status`) which execute with zero friction through the Fast-Path classifier.
4. **When Soft Denied**: If a command is flagged for confirmation (`decision: force_ask`), clearly explain why the action requires user approval.

# Presentation Notes: Sandbox Hardening + Relanto PR Review Skill

This fork carries two pieces of work done ahead of a presentation: a gateway/sandbox
security hardening pass on a local OpenClaw install, and a custom skill for automated
GitHub PR review.

## 1. Gateway + Sandbox Hardening (`openclaw.json`)

Local config at `~/.openclaw/openclaw.json` was changed:

- **`agents.defaults.sandbox`**: `mode` changed from `"off"` to `"non-main"` (sandboxes
  every non-main agent), with `scope: "agent"` and `backend: "docker"` so isolation
  actually runs in Docker per agent.
- **`tools.sandbox.tools.allow`**: `["web_fetch"]` — explicitly exempts `web_fetch` from
  the sandbox restriction so sandboxed agents can still fetch URLs (e.g. GitHub diffs).
- **`gateway.bind`**: changed from `"lan"` to `"loopback"` — the gateway now only listens
  locally and is not reachable from the network.

## 2. `relanto-pr-review` Skill

Custom skill at `~/.openclaw/workspace/skills/relanto-pr-review/SKILL.md`. Given a GitHub
PR URL or diff, the agent:

1. Fetches the PR diff from the GitHub API (`.diff` endpoint or
   `Accept: application/vnd.github.v3.diff`).
2. Reviews it in a fixed **Relanto structure**: `Summary`, `Blocking Issues`,
   `Suggestions`.
3. Asks for explicit confirmation before posting anything.
4. If confirmed, resolves a GitHub token from the user's prompt or the
   `GITHUB_TOKEN`/`GH_TOKEN` environment variable — never a placeholder/fabricated
   token — and posts the review as a comment via the GitHub issue-comments API.

No auto-post without confirmation, and no fake credentials on a 401 — if no real token
is available, the agent asks for one instead of guessing.

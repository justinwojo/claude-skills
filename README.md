# Claude Skills

Skills for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

Install via the Claude Code plugin system:

```
/plugin marketplace add justinwojo/claude-skills
/plugin install swift-binding-assistant@justinwojo-claude-skills
```

Or manually copy individual skills into `.claude/skills/` (project-scoped) or `~/.claude/skills/` (global).

## Skills

### swift-binding-assistant

Create .NET C# bindings for Swift and Objective-C Apple platform libraries — go from an SPM package URL or xcframework to a ready-to-use NuGet package.

Built on top of [swift-dotnet-bindings](https://github.com/justinwojo/swift-dotnet-bindings) and [spm-to-xcframework](https://github.com/justinwojo/spm-to-xcframework).

**Supported platforms:** iOS, macOS, Mac Catalyst, tvOS

**Supported framework types:** Swift, Objective-C, and mixed — auto-detected during build.

**Workflow:**

```
SPM package URL / xcframework / GitHub release
  → Check prerequisites (macOS, Xcode, .NET 10)
  → Build xcframework from SPM (if needed)
  → Create binding project (dotnet new swift-binding)
  → Build & diagnose errors (auto-fetches latest troubleshooting docs)
  → Package as NuGet (.nupkg)
  → Optional: review generated binding for completeness
```

**Example usage:**

> "Bind the Nuke Swift library for iOS"
>
> "Create a C# binding for this xcframework at ~/frameworks/MyLib.xcframework"
>
> "I have a binding project that's failing to build, help me fix it"

**Prerequisites:** macOS with Xcode and .NET 10 SDK. No additional configuration needed.

See [swift-binding-assistant/SKILL.md](swift-binding-assistant/SKILL.md) for the full skill specification.

---

### ai-pair-programming

Query external LLMs (OpenAI/ChatGPT, Google Gemini, xAI Grok) for code review, improvement suggestions, and collaborative problem-solving.

**Supported providers:**
- OpenAI (gpt-5.4, gpt-5, gpt-4o, o3-mini)
- Google Gemini (gemini-3.1-pro-preview, gemini-3-flash-preview, gemini-2.5-flash)
- xAI Grok (grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning)

**Setup:** Set API key environment variables for the providers you want to use: `OPENAI_API_KEY`, `GOOGLE_AI_API_KEY`, `XAI_API_KEY`.

Optionally override default models: `OPENAI_MODEL`, `GEMINI_MODEL`, `GROK_MODEL`.

See [ai-pair-programming/SKILL.md](ai-pair-programming/SKILL.md) for full documentation.

---

### session-orchestrator

Autonomously execute multi-session design docs using agent teams. A lead orchestrator reads your design doc, spawns one worker per session sequentially (each with fresh context), verifies deliverables, and reports results.

**How it works:**

```
Lead (reads design doc, creates team, directs everything)
 ├── session-1-worker → implements, validates, reviews, commits
 ├── session-2-worker → picks up from session 1, same workflow
 └── final validation, cleanup, summary to user
```

**Setup:** Requires the experimental agent teams feature. Add to `~/.claude/settings.json`:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

If the [ai-pair-programming](#ai-pair-programming) skill is installed and configured, workers automatically get external AI code review before committing. Without it, workers perform a self-review instead.

**Stuck detection:** If you use [iTerm2](https://iterm2.com) with the `it2` CLI and Python API enabled, the orchestrator automatically monitors worker terminal sessions via `/loop` and intervenes when a worker hangs — sending Ctrl+C and escalating to "resume" nudges as needed. Without iTerm2, the lead still receives teammate messages and idle notifications for basic visibility.

**Example usage:**

> "Orchestrate this design doc: docs/refactor-plan.md"
>
> "Run the sessions from my design doc"

See [session-orchestrator/SKILL.md](session-orchestrator/SKILL.md) for the full skill specification.

---

### smart-permissions

A PreToolUse hook that replaces the built-in permission prompts with configurable, rule-based auto-approval — safe commands execute immediately, dangerous patterns are blocked, and everything else falls through to an optional LLM safety evaluation or the standard permission prompt (with "Always allow" support).

Includes MCP tool support with glob patterns for granular read-only vs write approval (e.g., `mcp__sentry__get_*`).

**Setup:** Install the plugin — no API keys required. Optionally set `SAFETY_HOOK_API_KEY` (plus `SAFETY_HOOK_API_URL` and `SAFETY_HOOK_MODEL`) for LLM fallback evaluation. Customize allowed commands/paths/MCP tools via `~/.claude/smart-permissions-config.json`.

See [smart-permissions/README.md](smart-permissions/README.md) for full documentation.

## License

MIT

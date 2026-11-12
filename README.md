# Claude Skills

Skills and plugins for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

Install via the Claude Code plugin system:

```
/plugin marketplace add justinwojo/claude-skills
/plugin install swift-binding-assistant@justinwojo-claude-skills
/plugin install smart-permissions@justinwojo-claude-skills
```

Or manually copy `swift-binding-assistant/` into `.claude/skills/` (project-scoped) or `~/.claude/skills/` (global). smart-permissions is hook-based and needs the plugin install.

## Plugins

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

### smart-permissions

A PreToolUse hook that replaces the built-in permission prompts with configurable, rule-based auto-approval — safe commands execute immediately, dangerous patterns are blocked, and everything else falls through to an optional LLM safety evaluation or the standard permission prompt (with "Always allow" support).

Includes MCP tool support with glob patterns for granular read-only vs write approval (e.g., `mcp__sentry__get_*`).

**Setup:** Install the plugin — no API keys required. Optionally set `SAFETY_HOOK_API_KEY` (plus `SAFETY_HOOK_API_URL` and `SAFETY_HOOK_MODEL`) for LLM fallback evaluation. Customize allowed commands/paths/MCP tools via `~/.claude/smart-permissions-config.json`.

See [smart-permissions/README.md](smart-permissions/README.md) for full documentation.

## License

MIT

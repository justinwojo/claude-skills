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

## License

MIT

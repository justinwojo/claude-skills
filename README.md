# Claude Skills

Personal collection of skills for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Skills

### ai-pair-programming

Query external LLMs (OpenAI/ChatGPT, Google Gemini, xAI Grok) for code review, improvement suggestions, and collaborative problem-solving.

**Supported providers:**
- OpenAI (gpt-5.2, gpt-5, gpt-4o, o3-mini)
- Google Gemini (gemini-3-pro-preview, gemini-3-flash-preview, gemini-2.5-flash)
- xAI Grok (grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning)

**Setup:** Set environment variables for providers you want to use:
- `OPENAI_API_KEY`
- `GOOGLE_AI_API_KEY`
- `XAI_API_KEY`

See [ai-pair-programming/SKILL.md](ai-pair-programming/SKILL.md) for full documentation.

### swift-binding-assistant

Guide users through creating .NET C# bindings for Swift iOS libraries. Takes a user from an SPM package URL or xcframework to a validated NuGet package using the [Swift.Bindings.Sdk](https://github.com/justinwojo/swift-dotnet-bindings).

**What it does:**
- Checks prerequisites (macOS, Xcode, .NET 10, iOS workload)
- Builds xcframeworks from SPM packages via [spm-to-xcframework](https://github.com/justinwojo/spm-to-xcframework)
- Creates and configures the binding project
- Diagnoses build errors using the latest project docs
- Packages the binding as a NuGet package
- Optionally reviews the generated binding for completeness

**Setup:** No configuration needed. Requires macOS with Xcode and .NET 10 SDK.

See [swift-binding-assistant/SKILL.md](swift-binding-assistant/SKILL.md) for full documentation.

## License

MIT

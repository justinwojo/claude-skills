---
name: ai-pair-programming
description: Enable AI pair programming by querying external LLMs (OpenAI/ChatGPT, Google Gemini, xAI Grok) with code files, plans, and project context. Default provider is OpenAI (gpt-5.4) — always use openai unless the user specifically requests other providers. Use when the user wants to get code review from another AI, ask for improvement suggestions, get feedback on a plan, consult multiple AIs for comparison, or get a second opinion on architecture decisions. Supports passing multiple files, project context (tech stack, frameworks), and additional context like "things we've tried". Triggers on "ask ChatGPT to review", "get feedback from GPT", "pair program with", "consult other AIs about", "ask Grok to review", "what does Gemini think".
---

# AI Pair Programming

Query external LLMs with rich context for code review, improvement suggestions, and collaborative problem-solving.

## Configuration

### API Keys (Required)
| Provider | Environment Variable |
|----------|---------------------|
| OpenAI/ChatGPT | `OPENAI_API_KEY` |
| Google Gemini | `GOOGLE_AI_API_KEY` |
| xAI Grok | `XAI_API_KEY` |

### Default Models (Optional)
Override default model selection per provider:
| Provider | Environment Variable | Default |
|----------|---------------------|---------|
| OpenAI | `OPENAI_MODEL` | gpt-5.4 |
| Gemini | `GEMINI_MODEL` | gemini-3.1-pro-preview |
| Grok | `GROK_MODEL` | grok-4.20-0309-reasoning |

Models can also be specified per-query via `--models openai:gpt-4-turbo`.

## Core Workflow

Build a query with these components:

### 1. Project Context (Optional but Recommended)
Describe the project's tech stack and architecture. Infer this from the codebase if the user doesn't specify — check package.json, .csproj, Cargo.toml, go.mod, etc. Examples:
```
--project "Node.js REST API with Express and PostgreSQL"
--project "Rust CLI tool using clap and tokio"
--project "Swift iOS app with SwiftUI and Combine"
```

### 2. Files (One or More)
Pass relevant files for the AI to analyze. Use full relative paths (not just filenames) so the external model understands the project structure:
- Source code files
- Test files for the code being reviewed
- Configuration files

### 3. Git Diff (Recommended for Reviews)
Include the diff to show what actually changed:
- `--diff` — unstaged changes (default)
- `--diff staged` — staged changes
- `--diff main` — diff against main branch
- `--diff <commit>` — diff against any commit/branch

### 4. Request Type
Specify what you need:
- **review** - Code review with structured output (Critical Issues / Improvements / Positive). Includes a system prompt that steers the model to cite file:line references and focus on the diff.
- **improve** - Improvement recommendations categorized by impact level. Includes a system prompt for structured output.
- **feedback** - General feedback on approach/plan
- **guidance** - Answer a question or provide direction

### 5. Target Models
**Default: `openai` (gpt-5.4).** Always use OpenAI/ChatGPT unless the user specifically requests other providers. Only add gemini/grok as secondary reviewers when explicitly asked.

Query one or more:
- `openai` (gpt-5.4, gpt-5.2, gpt-5, gpt-4o, o3-mini)
- `gemini` (gemini-3.1-pro-preview, gemini-3-pro-preview, gemini-3-flash-preview, gemini-2.5-flash)
- `grok` (grok-4.20-0309-reasoning, grok-4.20-0309-non-reasoning, grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning, grok-4.20-multi-agent-0309)
  - **Note:** `grok-4.20-multi-agent-0309` has ~150K tokens of internal overhead per request — avoid for simple reviews.

### 6. Temperature Selection
Use `--temperature` (or `-t`) to control response creativity. Choose based on the task:

| Temperature | When to Use |
|-------------|-------------|
| **0.2** | Bug hunting, security review, finding specific issues, factual questions |
| **0.4** | Code review, explaining code, analyzing logic, technical Q&A |
| **0.5** | Refactoring suggestions, code improvements, best practices |
| **0.7** | General guidance, architectural feedback, plan review |
| **0.8** | Brainstorming approaches, exploring alternatives, creative solutions |
| **1.0** | Novel ideas, unconventional approaches, "what if" scenarios |

**Quick guide:**
- Precision tasks (bugs, security, correctness) → **low (0.2-0.4)**
- Balanced tasks (review, improve, feedback) → **medium (0.5-0.7)**
- Creative tasks (brainstorm, explore options) → **high (0.8-1.0)**

## Scripts

### query_llm.py - Single or Multi-Model Query
```bash
# Defaults to --request review --temperature 0.4
python scripts/query_llm.py \
  --models openai \
  --files src/handlers.ts src/converters/request.ts \
  --diff main \
  --project "Node.js proxy server with Fastify" \
  --context "Recently added debug logging, want to verify no performance regressions"
```

### build_context.py - Build Context Package
Assembles files and context into a structured prompt for reuse:
```bash
python scripts/build_context.py \
  --files docs/plan.md src/feature.ts \
  --project "TypeScript API server" \
  --output context.json
```

## Preparing Context (Claude's Responsibility)

Before calling query_llm.py, gather the right context for the external model. The external model only sees what you send — it cannot explore the codebase.

### Infer Project Context
If the user doesn't provide `--project`, infer it from the repo. Check for package.json, .csproj, Cargo.toml, go.mod, pyproject.toml, build.gradle, etc. to determine language, framework, and purpose. Pass a concise summary.

### For Code Reviews
1. **Always include the diff** (`--diff main` or `--diff staged`). The diff is the most important context — it shows what changed.
2. **Include the changed files** — The full source files give surrounding context for the diff.
3. **Include related test files** — Use Glob/Grep to find tests for the changed code and include them.
4. **Include files that import/depend on the changed code** — If a function signature changed, include callers.
5. **Use full relative paths** for `--files` (e.g., `src/server/handlers.ts` not just `handlers.ts`).

### For Improvements
1. Include the files to improve plus their tests.
2. Include any interfaces, base classes, or types the code depends on.

### For Plan Feedback
1. Include the plan document.
2. Include key source files the plan references so the model can assess feasibility.

### Token Budget
Keep reviews under ~200K input tokens. Most providers charge higher rates beyond that threshold. The script warns at 50K and 100K. To keep reviews sharp and cost-effective:
- Send the most relevant files, not every file in the repo.
- For large files (1000+ lines), consider sending only the changed sections or using Grep output instead.
- The diff alone is often sufficient context — only include full files when the reviewer needs surrounding code to judge correctness.

## Usage Patterns

### Code Review
```
Ask ChatGPT to review the recent changes.
Include the diff against main.
```

### Plan Feedback
```
Ask GPT for feedback on docs/refactor-plan.md
Additional context: We tried a gradual migration but had state sync issues
```

### Improvement Suggestions
```
Ask ChatGPT to suggest improvements for src/server/handlers.ts
Focus on performance and error handling.
```

### Multi-Model Comparison
```
Query ChatGPT, Grok, and Gemini about the best approach for caching in this project.
```

## Response Handling

When querying multiple models, responses are returned with clear attribution:
```
=== OPENAI (gpt-5.4) ===
[OpenAI's response]

=== GROK (grok-4.20-0309-reasoning) ===
[Grok's response]
```

### Verifying and Presenting Results
IMPORTANT: External models may hallucinate or make claims about code they misread. Before presenting their feedback to the user:

1. **Verify file:line references** — If the external model cites a specific file and line, spot-check that the code at that location matches what the model claims. Use Read/Grep to confirm.
2. **Flag unverifiable claims** — If the model references code or patterns not included in the files sent, note this to the user (e.g., "Grok flagged X but this wasn't in the provided files — worth checking").
3. **Discard hallucinated findings** — If a claimed issue clearly doesn't exist in the actual code, drop it rather than confusing the user.

### Synthesizing Multiple Responses
When presenting results from multiple models:
- **Agreement** — Issues flagged by multiple models are high confidence. Lead with these.
- **Unique findings** — Valuable insights from only one model. Present with attribution.
- **Conflicts** — Contradicting recommendations. Present both sides and flag for the user to decide.
- **Quality ranking** — If one model's response is clearly better grounded (cites specific lines, matches the actual diff), weight it accordingly.

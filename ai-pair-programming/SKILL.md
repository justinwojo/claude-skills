---
name: ai-pair-programming
description: Enable AI pair programming by querying external LLMs (OpenAI/ChatGPT, Google Gemini, xAI Grok) with code files, plans, and project context. Use when the user wants to get code review from another AI, ask for improvement suggestions, get feedback on a plan, consult multiple AIs for comparison, or get a second opinion on architecture decisions. Supports passing multiple files, project context (tech stack, frameworks), and additional context like "things we've tried". Triggers on "ask Grok to review", "what does Gemini think about this code", "get feedback from GPT and Gemini", "pair program with", "consult other AIs about".
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
| OpenAI | `OPENAI_MODEL` | gpt-4o |
| Gemini | `GEMINI_MODEL` | gemini-2.0-flash |
| Grok | `GROK_MODEL` | grok-2 |

Models can also be specified per-query via `--models openai:gpt-4-turbo`.

## Core Workflow

Build a query with these components:

### 1. Project Context (Optional but Recommended)
Describe the project's tech stack and architecture:
```
Project: .NET 10 mobile app using .NET for iOS/Android with MvvmCross framework
```

### 2. Files (One or More)
Pass relevant files for the AI to analyze:
- Source code files
- Markdown plan files
- Configuration files
- Test files

### 3. Request Type
Specify what you need:
- **review** - Code review with issues and suggestions
- **improve** - Specific improvement recommendations
- **feedback** - General feedback on approach/plan
- **guidance** - Answer a question or provide direction

### 4. Additional Context (Optional)
Include relevant background:
- Things already tried
- Constraints or requirements
- Specific concerns to address
- Related decisions already made

### 5. Target Models
Query one or more:
- `openai` (gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
- `gemini` (gemini-2.0-flash, gemini-1.5-pro)
- `grok` (grok-2, grok-2-mini, grok-4-1-fast-reasoning)

### 6. Temperature Selection
Use `--temperature` (or `-t`) to control response creativity. Choose based on the task:

| Temperature | When to Use |
|-------------|-------------|
| **0.2** | Bug hunting, security review, finding specific issues, factual questions |
| **0.4** | Code review, explaining code, analyzing logic, technical Q&A |
| **0.5** | Refactoring suggestions, code improvements, best practices |
| **0.7** | General guidance, architectural feedback, plan review (default) |
| **0.8** | Brainstorming approaches, exploring alternatives, creative solutions |
| **1.0** | Novel ideas, unconventional approaches, "what if" scenarios |

**Quick guide:**
- Precision tasks (bugs, security, correctness) → **low (0.2-0.4)**
- Balanced tasks (review, improve, feedback) → **medium (0.5-0.7)**
- Creative tasks (brainstorm, explore options) → **high (0.8-1.0)**

## Scripts

### query_llm.py - Single or Multi-Model Query
```bash
python scripts/query_llm.py \
  --models grok,gemini \
  --files src/ViewModels/MainViewModel.cs src/Services/ApiService.cs \
  --project "NET 10 iOS/Android app with MvvmCross" \
  --request review \
  --temperature 0.4 \
  --context "We tried using HttpClientFactory but had DI issues"
```

### build_context.py - Build Context Package
Assembles files and context into a structured prompt:
```bash
python scripts/build_context.py \
  --files plan.md src/Feature.cs \
  --project "..." \
  --output context.json
```

## Usage Patterns

### Code Review
```
Query Grok and Gemini to review these files:
- src/ViewModels/LoginViewModel.cs
- src/Services/AuthService.cs

Project context: .NET 10 MAUI app with MvvmCross and Refit for API calls

Additional context: We're seeing occasional crashes on iOS during token refresh
```

### Plan Feedback
```
Ask GPT-4 and Gemini for feedback on docs/refactor-plan.md

Project context: Large React app migrating from Redux to Zustand

Additional context: We tried a gradual migration but had state sync issues between stores
```

### Improvement Suggestions
```
Ask Grok to suggest improvements for src/DataProcessor.cs

Project context: .NET 8 background worker processing 10k messages/minute

Request: Focus on performance and memory allocation
```

### Multi-Model Comparison
```
Query all three AIs about the best approach for offline sync

Project context: Mobile app with SQLite local DB and REST API backend

Additional context:
- Tried conflict-free replicated data types (CRDTs) but too complex
- Need to handle merge conflicts gracefully
- Users may be offline for days
```

## Response Handling

When querying multiple models, responses are returned with clear attribution:
```
=== GROK (grok-2) ===
[Grok's response]

=== GEMINI (gemini-2.0-flash) ===
[Gemini's response]

=== OPENAI (gpt-4o) ===
[OpenAI's response]
```

Synthesize insights from multiple responses, noting:
- Areas of agreement (high confidence)
- Unique suggestions from each model
- Conflicting recommendations (flag for user decision)

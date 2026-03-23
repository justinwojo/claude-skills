#!/usr/bin/env python3
"""
Query one or more LLMs with files, project context, and additional context.

Usage:
    python query_llm.py --models grok,gemini --files file1.cs file2.cs \
        --project "NET 10 app with MvvmCross" --request review \
        --context "Tried X but had issues with Y"
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# API Configuration
API_CONFIG = {
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "model_env_key": "OPENAI_MODEL",
        "base_url": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-5.4",
        "models": ["gpt-5.4", "gpt-5.2", "gpt-5", "gpt-4o", "o3-mini"],
    },
    "gemini": {
        "env_key": "GOOGLE_AI_API_KEY",
        "model_env_key": "GEMINI_MODEL",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "default_model": "gemini-3.1-pro-preview",
        "models": ["gemini-3.1-pro-preview", "gemini-3-pro-preview", "gemini-3-flash-preview", "gemini-2.5-flash"],
    },
    "grok": {
        "env_key": "XAI_API_KEY",
        "model_env_key": "GROK_MODEL",
        "base_url": "https://api.x.ai/v1/chat/completions",
        "responses_url": "https://api.x.ai/v1/responses",
        "default_model": "grok-4.20-0309-reasoning",
        "models": [
            "grok-4.20-0309-reasoning",
            "grok-4.20-multi-agent-0309",
            "grok-4.20-0309-non-reasoning",
            "grok-4-1-fast-reasoning",
            "grok-4-1-fast-non-reasoning",
        ],
    },
}


def _is_grok_responses_model(model: str) -> bool:
    """Check if a Grok model requires the /v1/responses endpoint."""
    return model.startswith("grok-4.20")


def get_default_model(provider: str) -> str:
    """Get default model for provider, checking env var first."""
    config = API_CONFIG.get(provider, {})
    # Check env var first, fall back to hardcoded default
    return os.environ.get(config.get("model_env_key", ""), config.get("default_model", ""))

REQUEST_PROMPTS = {
    "review": "Please review the following code. Identify potential issues, bugs, security concerns, and areas for improvement. Be specific and actionable.",
    "improve": "Please suggest specific improvements for the following code. Focus on code quality, performance, maintainability, and best practices.",
    "feedback": "Please provide feedback on the following plan/approach. Consider feasibility, potential issues, and suggestions for refinement.",
    "guidance": "Please provide guidance on the following question or problem. Be specific and practical.",
}

ANTI_HALLUCINATION_RULES = """
## Anti-Hallucination Rules
- ONLY comment on code you can see in the provided files. Never assume or guess about code not shown.
- If you cannot determine something from the provided code, say "I can't determine this from the provided files" rather than speculating.
- If a section has no findings, omit it entirely. Do not pad your response with filler.
- A short, accurate review is better than a long one that guesses. If the code is straightforward and correct, say so briefly.
- Never invent file paths, function names, or line numbers. Only reference what is present in the provided code."""

SYSTEM_PROMPTS = {
    "review": f"""You are an expert code reviewer. Follow these rules strictly:

## Response Format
Structure your review with these sections (omit any section with no findings):
- **Critical Issues**: Bugs, security vulnerabilities, data loss risks. Include file path and line number.
- **Improvements**: Code quality, performance, maintainability suggestions. Include file path and line number.
- **Positive**: What's done well (brief).

## Rules
- When a git diff is provided, focus your review on the CHANGED lines. The diff shows what's new — that's what needs review.
- Always reference specific file paths and line numbers (e.g., `src/server/handlers.ts:42`).
- Distinguish between issues in NEW code (from the diff) vs PRE-EXISTING issues in the surrounding context.
- Be specific and actionable. "Consider improving error handling" is useless. "Add null check for `user` at line 42 — `getProfile()` can return null when session expires" is useful.
{ANTI_HALLUCINATION_RULES}""",

    "improve": f"""You are an expert software engineer focused on code improvement. Follow these rules:

## Response Format (omit any section with no findings)
- **High Impact**: Changes that significantly improve performance, reliability, or maintainability. Include file:line.
- **Medium Impact**: Code quality and best practice improvements. Include file:line.
- **Low Impact / Style**: Minor cleanups (brief, don't over-index on these).

## Rules
- When a git diff is provided, focus improvements on the changed code.
- Always include the specific file path and line number for each suggestion.
- Provide concrete code examples for non-trivial suggestions.
- If you cannot determine the full impact of a change, say what you'd need to see to be sure.
{ANTI_HALLUCINATION_RULES}""",

    "feedback": f"""You are a senior technical advisor providing feedback on a plan or approach. Be specific about:
- Feasibility concerns with concrete reasoning
- Potential issues you foresee and why
- Alternative approaches worth considering
- What information would be needed to make a more confident assessment
{ANTI_HALLUCINATION_RULES}""",

    "guidance": None,  # No system prompt for general guidance
}


@dataclass
class QueryContext:
    """Container for all context passed to LLMs."""
    files: dict[str, str]  # filepath -> content
    project_context: Optional[str]
    request_type: str
    additional_context: Optional[str]
    custom_prompt: Optional[str]
    diff: Optional[str] = None


def read_files(file_paths: list[str]) -> dict[str, str]:
    """Read multiple files and return as dict of filepath -> content.
    Preserves relative or absolute path as the key for architectural context."""
    files = {}
    for path in file_paths:
        p = Path(path)
        if not p.exists():
            print(f"Warning: File not found: {path}", file=sys.stderr)
            continue
        try:
            files[str(path)] = p.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Warning: Could not read {path}: {e}", file=sys.stderr)
    return files


def get_git_diff(diff_target: str) -> Optional[str]:
    """Get git diff output. diff_target can be a branch, commit, or 'staged'/'unstaged'."""
    try:
        if diff_target == "staged":
            cmd = ["git", "diff", "--cached"]
        elif diff_target == "unstaged":
            cmd = ["git", "diff"]
        else:
            # Branch name or commit hash
            cmd = ["git", "diff", diff_target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Warning: git diff failed: {result.stderr.strip()}", file=sys.stderr)
            return None
        return result.stdout if result.stdout.strip() else None
    except FileNotFoundError:
        print("Warning: git not found", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("Warning: git diff timed out", file=sys.stderr)
        return None


LANG_MAP = {
    ".cs": "csharp", ".py": "python", ".js": "javascript",
    ".ts": "typescript", ".jsx": "jsx", ".tsx": "tsx",
    ".java": "java", ".kt": "kotlin", ".swift": "swift",
    ".go": "go", ".rs": "rust", ".rb": "ruby",
    ".md": "markdown", ".json": "json", ".xml": "xml",
    ".yaml": "yaml", ".yml": "yaml", ".sql": "sql",
}


def build_prompt(ctx: QueryContext) -> str:
    """Build the full prompt from context components."""
    parts = []

    # Project context
    if ctx.project_context:
        parts.append(f"## Project Context\n{ctx.project_context}")

    # Request type instruction
    if ctx.custom_prompt:
        parts.append(f"## Request\n{ctx.custom_prompt}")
    else:
        parts.append(f"## Request\n{REQUEST_PROMPTS.get(ctx.request_type, REQUEST_PROMPTS['guidance'])}")

    # Git diff (before files — shows what changed, files show full context)
    if ctx.diff:
        parts.append(f"## Git Diff (Changed Code)\nThe following diff shows what was changed. Focus your review on these changes.\n```diff\n{ctx.diff}\n```")

    # Files
    if ctx.files:
        parts.append("## Files" + (" (Full Context)" if ctx.diff else ""))
        for filepath, content in ctx.files.items():
            ext = Path(filepath).suffix.lower()
            lang = LANG_MAP.get(ext, "")
            parts.append(f"### {filepath}\n```{lang}\n{content}\n```")

    # Additional context
    if ctx.additional_context:
        parts.append(f"## Additional Context\n{ctx.additional_context}")

    return "\n\n".join(parts)


def _build_openai_messages(prompt: str, system_prompt: Optional[str]) -> list[dict]:
    """Build messages array for OpenAI-compatible APIs."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    return messages


@dataclass
class LLMResponse:
    """Response from an LLM including content and token usage."""
    content: str
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None


def _extract_openai_usage(result: dict) -> dict:
    """Extract token usage from OpenAI-compatible response."""
    usage = result.get("usage", {})
    return {
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
    }


def _extract_gemini_usage(result: dict) -> dict:
    """Extract token usage from Gemini response."""
    usage = result.get("usageMetadata", {})
    return {
        "input_tokens": usage.get("promptTokenCount"),
        "output_tokens": usage.get("candidatesTokenCount"),
        "total_tokens": usage.get("totalTokenCount"),
    }


def query_openai(prompt: str, model: str, api_key: str, temperature: float = 0.7,
                 system_prompt: Optional[str] = None) -> LLMResponse:
    """Query OpenAI API."""
    import urllib.request

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    data = json.dumps({
        "model": model,
        "messages": _build_openai_messages(prompt, system_prompt),
        "temperature": temperature,
    }).encode()

    req = urllib.request.Request(
        API_CONFIG["openai"]["base_url"],
        data=data,
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read().decode())
        return LLMResponse(
            content=result["choices"][0]["message"]["content"],
            **_extract_openai_usage(result),
        )


def query_gemini(prompt: str, model: str, api_key: str, temperature: float = 0.7,
                 system_prompt: Optional[str] = None) -> LLMResponse:
    """Query Google Gemini API."""
    import urllib.request

    url = f"{API_CONFIG['gemini']['base_url']}/{model}:generateContent?key={api_key}"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    body: dict = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }
    if system_prompt:
        body["systemInstruction"] = {"parts": [{"text": system_prompt}]}
    data = json.dumps(body).encode()

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read().decode())
        return LLMResponse(
            content=result["candidates"][0]["content"]["parts"][0]["text"],
            **_extract_gemini_usage(result),
        )


def query_grok(prompt: str, model: str, api_key: str, temperature: float = 0.7,
               system_prompt: Optional[str] = None) -> LLMResponse:
    """Query xAI Grok API."""
    import urllib.request
    import urllib.error

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    data = json.dumps({
        "model": model,
        "messages": _build_openai_messages(prompt, system_prompt),
        "temperature": temperature,
    }).encode()

    req = urllib.request.Request(
        API_CONFIG["grok"]["base_url"],
        data=data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode())
            return LLMResponse(
                content=result["choices"][0]["message"]["content"],
                **_extract_openai_usage(result),
            )
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {error_body}")


def query_grok_responses(prompt: str, model: str, api_key: str, temperature: float = 0.7,
                         system_prompt: Optional[str] = None) -> LLMResponse:
    """Query xAI Grok via the /v1/responses endpoint (required for grok-4.20 models)."""
    import urllib.request
    import urllib.error

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    input_messages = []
    if system_prompt:
        input_messages.append({"role": "system", "content": system_prompt})
    input_messages.append({"role": "user", "content": prompt})

    data = json.dumps({
        "model": model,
        "input": input_messages,
        "temperature": temperature,
        "store": False,
    }).encode()

    req = urllib.request.Request(
        API_CONFIG["grok"]["responses_url"],
        data=data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode())
            # Extract text from responses API format
            text = ""
            for output_item in result.get("output", []):
                for content_item in output_item.get("content", []):
                    if content_item.get("type") == "output_text":
                        text += content_item.get("text", "")
            usage = result.get("usage", {})
            return LLMResponse(
                content=text,
                input_tokens=usage.get("input_tokens"),
                output_tokens=usage.get("output_tokens"),
                total_tokens=usage.get("total_tokens"),
            )
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {error_body}")


def query_provider(provider: str, model: Optional[str], prompt: str, temperature: float = 0.7,
                   system_prompt: Optional[str] = None) -> tuple[str, str, LLMResponse]:
    """Query a single provider and return (provider, model, LLMResponse)."""
    config = API_CONFIG.get(provider)
    if not config:
        return provider, "", LLMResponse(content=f"Error: Unknown provider '{provider}'")

    api_key = os.environ.get(config["env_key"])
    if not api_key:
        return provider, "", LLMResponse(content=f"Error: {config['env_key']} not set")

    model = model or get_default_model(provider)

    query_funcs = {
        "openai": query_openai,
        "gemini": query_gemini,
        "grok": query_grok,
    }

    try:
        # Route grok-4.20 models to the /v1/responses endpoint
        if provider == "grok" and _is_grok_responses_model(model):
            response = query_grok_responses(prompt, model, api_key, temperature, system_prompt)
        else:
            response = query_funcs[provider](prompt, model, api_key, temperature, system_prompt)
        return provider, model, response
    except Exception as e:
        return provider, model, LLMResponse(content=f"Error: {str(e)}")


def parse_model_spec(spec: str) -> tuple[str, Optional[str]]:
    """Parse 'provider' or 'provider:model' format."""
    if ":" in spec:
        provider, model = spec.split(":", 1)
        return provider.lower(), model
    return spec.lower(), None


def main():
    parser = argparse.ArgumentParser(description="Query LLMs with code and context")
    parser.add_argument("--models", "-m", required=True,
                        help="Comma-separated list of models (e.g., grok,gemini,openai:gpt-4-turbo)")
    parser.add_argument("--files", "-f", nargs="+", default=[],
                        help="Files to include in the query")
    parser.add_argument("--diff", "-d", nargs="?", const="unstaged", default=None,
                        help="Include git diff. Use: --diff (unstaged), --diff staged, --diff main, --diff <commit>")
    parser.add_argument("--project", "-p", default=None,
                        help="Project context (tech stack, framework, etc.)")
    parser.add_argument("--request", "-r", default="review",
                        choices=["review", "improve", "feedback", "guidance"],
                        help="Type of request")
    parser.add_argument("--context", "-c", default=None,
                        help="Additional context (things tried, constraints, etc.)")
    parser.add_argument("--prompt", default=None,
                        help="Custom prompt (overrides --request)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output file (default: stdout)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--temperature", "-t", type=float, default=0.4,
                        help="Temperature (0.0=deterministic, 1.0=creative). Default: 0.4")

    args = parser.parse_args()

    # Parse model specifications
    model_specs = [parse_model_spec(m.strip()) for m in args.models.split(",")]

    # Get git diff if requested
    diff = get_git_diff(args.diff) if args.diff else None
    if args.diff and not diff:
        print("Note: --diff requested but no diff output (clean working tree?)", file=sys.stderr)

    # Build context
    ctx = QueryContext(
        files=read_files(args.files),
        project_context=args.project,
        request_type=args.request,
        additional_context=args.context,
        custom_prompt=args.prompt,
        diff=diff,
    )

    prompt = build_prompt(ctx)

    # Estimate token count and warn if large (~4 chars per token)
    estimated_tokens = len(prompt) // 4
    if estimated_tokens > 200_000:
        print(f"Warning: Estimated prompt size is ~{estimated_tokens:,} tokens. "
              f"Exceeds 200K — most providers charge higher rates beyond this. "
              f"Consider sending fewer/smaller files.",
              file=sys.stderr)
    elif estimated_tokens > 100_000:
        print(f"Warning: Estimated prompt size is ~{estimated_tokens:,} tokens. "
              f"Approaching 200K limit. Consider sending fewer/smaller files.",
              file=sys.stderr)
    elif estimated_tokens > 50_000:
        print(f"Note: Estimated prompt size is ~{estimated_tokens:,} tokens.", file=sys.stderr)

    # Get system prompt for this request type
    system_prompt = SYSTEM_PROMPTS.get(args.request) if not args.prompt else None

    # Query all models in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=len(model_specs)) as executor:
        futures = {
            executor.submit(query_provider, provider, model, prompt, args.temperature, system_prompt): (provider, model)
            for provider, model in model_specs
        }
        for future in as_completed(futures):
            provider, model, response = future.result()
            results[provider] = {"model": model, "response": response}

    # Format token usage line
    def format_usage(resp: LLMResponse) -> str:
        parts = []
        if resp.input_tokens is not None:
            parts.append(f"input: {resp.input_tokens:,}")
        if resp.output_tokens is not None:
            parts.append(f"output: {resp.output_tokens:,}")
        if resp.total_tokens is not None:
            parts.append(f"total: {resp.total_tokens:,}")
        return f"Tokens: {' | '.join(parts)}" if parts else ""

    # Output
    if args.json:
        json_results = {}
        for provider, data in results.items():
            resp = data["response"]
            json_results[provider] = {
                "model": data["model"],
                "response": resp.content,
                "usage": {
                    "input_tokens": resp.input_tokens,
                    "output_tokens": resp.output_tokens,
                    "total_tokens": resp.total_tokens,
                },
            }
        output = json.dumps(json_results, indent=2)
    else:
        output_parts = []
        for provider, data in results.items():
            resp = data["response"]
            header = f"=== {provider.upper()} ({data['model']}) ==="
            usage = format_usage(resp)
            section = f"{header}\n{resp.content}"
            if usage:
                section += f"\n\n_{usage}_"
            output_parts.append(section)
        output = "\n\n".join(output_parts)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Output written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

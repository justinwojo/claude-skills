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
        "default_model": "gpt-4o",
        "models": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    },
    "gemini": {
        "env_key": "GOOGLE_AI_API_KEY",
        "model_env_key": "GEMINI_MODEL",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "default_model": "gemini-2.0-flash",
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
    },
    "grok": {
        "env_key": "XAI_API_KEY",
        "model_env_key": "GROK_MODEL",
        "base_url": "https://api.x.ai/v1/chat/completions",
        "default_model": "grok-2",
        "models": ["grok-2", "grok-2-mini", "grok-4-1-fast-reasoning"],
    },
}


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


@dataclass
class QueryContext:
    """Container for all context passed to LLMs."""
    files: dict[str, str]  # filename -> content
    project_context: Optional[str]
    request_type: str
    additional_context: Optional[str]
    custom_prompt: Optional[str]


def read_files(file_paths: list[str]) -> dict[str, str]:
    """Read multiple files and return as dict of filename -> content."""
    files = {}
    for path in file_paths:
        p = Path(path)
        if not p.exists():
            print(f"Warning: File not found: {path}", file=sys.stderr)
            continue
        try:
            files[p.name] = p.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Warning: Could not read {path}: {e}", file=sys.stderr)
    return files


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

    # Files
    if ctx.files:
        parts.append("## Files")
        for filename, content in ctx.files.items():
            # Detect language from extension for code fence
            ext = Path(filename).suffix.lower()
            lang_map = {
                ".cs": "csharp", ".py": "python", ".js": "javascript",
                ".ts": "typescript", ".jsx": "jsx", ".tsx": "tsx",
                ".java": "java", ".kt": "kotlin", ".swift": "swift",
                ".go": "go", ".rs": "rust", ".rb": "ruby",
                ".md": "markdown", ".json": "json", ".xml": "xml",
                ".yaml": "yaml", ".yml": "yaml", ".sql": "sql",
            }
            lang = lang_map.get(ext, "")
            parts.append(f"### {filename}\n```{lang}\n{content}\n```")

    # Additional context
    if ctx.additional_context:
        parts.append(f"## Additional Context\n{ctx.additional_context}")

    return "\n\n".join(parts)


def query_openai(prompt: str, model: str, api_key: str, temperature: float = 0.7) -> str:
    """Query OpenAI API."""
    import urllib.request

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    data = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
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
        return result["choices"][0]["message"]["content"]


def query_gemini(prompt: str, model: str, api_key: str, temperature: float = 0.7) -> str:
    """Query Google Gemini API."""
    import urllib.request

    url = f"{API_CONFIG['gemini']['base_url']}/{model}:generateContent?key={api_key}"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AI-Pair-Programming/1.0",
    }
    data = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temperature},
    }).encode()

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read().decode())
        return result["candidates"][0]["content"]["parts"][0]["text"]


def query_grok(prompt: str, model: str, api_key: str, temperature: float = 0.7) -> str:
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
        "messages": [{"role": "user", "content": prompt}],
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
            return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {error_body}")


def query_provider(provider: str, model: Optional[str], prompt: str, temperature: float = 0.7) -> tuple[str, str, str]:
    """Query a single provider and return (provider, model, response)."""
    config = API_CONFIG.get(provider)
    if not config:
        return provider, "", f"Error: Unknown provider '{provider}'"

    api_key = os.environ.get(config["env_key"])
    if not api_key:
        return provider, "", f"Error: {config['env_key']} not set"

    model = model or get_default_model(provider)

    query_funcs = {
        "openai": query_openai,
        "gemini": query_gemini,
        "grok": query_grok,
    }

    try:
        response = query_funcs[provider](prompt, model, api_key, temperature)
        return provider, model, response
    except Exception as e:
        return provider, model, f"Error: {str(e)}"


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
    parser.add_argument("--project", "-p", default=None,
                        help="Project context (tech stack, framework, etc.)")
    parser.add_argument("--request", "-r", default="guidance",
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
    parser.add_argument("--temperature", "-t", type=float, default=0.7,
                        help="Temperature (0.0=deterministic, 1.0=creative). Default: 0.7")

    args = parser.parse_args()

    # Parse model specifications
    model_specs = [parse_model_spec(m.strip()) for m in args.models.split(",")]

    # Build context
    ctx = QueryContext(
        files=read_files(args.files),
        project_context=args.project,
        request_type=args.request,
        additional_context=args.context,
        custom_prompt=args.prompt,
    )

    prompt = build_prompt(ctx)

    # Query all models in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=len(model_specs)) as executor:
        futures = {
            executor.submit(query_provider, provider, model, prompt, args.temperature): (provider, model)
            for provider, model in model_specs
        }
        for future in as_completed(futures):
            provider, model, response = future.result()
            results[provider] = {"model": model, "response": response}

    # Output
    if args.json:
        output = json.dumps(results, indent=2)
    else:
        output_parts = []
        for provider, data in results.items():
            header = f"=== {provider.upper()} ({data['model']}) ==="
            output_parts.append(f"{header}\n{data['response']}")
        output = "\n\n".join(output_parts)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Output written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

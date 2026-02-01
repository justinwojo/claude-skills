#!/usr/bin/env python3
"""
Build a context package from files and project info.

Useful for preparing context that can be reused across multiple queries
or saved for later reference.

Usage:
    python build_context.py \
        --files src/App.cs src/Services/Api.cs \
        --project "NET 10 mobile app" \
        --context "Tried X, need help with Y" \
        --output context.json
"""

import argparse
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class ContextPackage:
    """Serializable context package."""
    files: dict[str, str]
    project_context: Optional[str]
    additional_context: Optional[str]
    file_summary: dict[str, dict]  # filename -> {lines, size, language}

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "ContextPackage":
        data = json.loads(json_str)
        return cls(**data)


def detect_language(filename: str) -> str:
    """Detect programming language from file extension."""
    ext = Path(filename).suffix.lower()
    lang_map = {
        ".cs": "C#", ".py": "Python", ".js": "JavaScript",
        ".ts": "TypeScript", ".jsx": "React JSX", ".tsx": "React TSX",
        ".java": "Java", ".kt": "Kotlin", ".swift": "Swift",
        ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
        ".md": "Markdown", ".json": "JSON", ".xml": "XML",
        ".yaml": "YAML", ".yml": "YAML", ".sql": "SQL",
        ".html": "HTML", ".css": "CSS", ".scss": "SCSS",
        ".sh": "Shell", ".ps1": "PowerShell", ".bat": "Batch",
    }
    return lang_map.get(ext, "Unknown")


def read_files(file_paths: list[str]) -> tuple[dict[str, str], dict[str, dict]]:
    """Read files and generate summaries."""
    files = {}
    summaries = {}

    for path in file_paths:
        p = Path(path)
        if not p.exists():
            print(f"Warning: File not found: {path}")
            continue
        try:
            content = p.read_text(encoding="utf-8")
            files[p.name] = content
            summaries[p.name] = {
                "path": str(p.absolute()),
                "lines": len(content.splitlines()),
                "size": len(content),
                "language": detect_language(p.name),
            }
        except Exception as e:
            print(f"Warning: Could not read {path}: {e}")

    return files, summaries


def main():
    parser = argparse.ArgumentParser(description="Build context package for LLM queries")
    parser.add_argument("--files", "-f", nargs="+", required=True,
                        help="Files to include")
    parser.add_argument("--project", "-p", default=None,
                        help="Project context description")
    parser.add_argument("--context", "-c", default=None,
                        help="Additional context")
    parser.add_argument("--output", "-o", required=True,
                        help="Output JSON file")

    args = parser.parse_args()

    files, summaries = read_files(args.files)

    package = ContextPackage(
        files=files,
        project_context=args.project,
        additional_context=args.context,
        file_summary=summaries,
    )

    Path(args.output).write_text(package.to_json(), encoding="utf-8")

    # Print summary
    print(f"Context package created: {args.output}")
    print(f"Files included: {len(files)}")
    for name, info in summaries.items():
        print(f"  - {name}: {info['lines']} lines, {info['language']}")
    total_size = sum(s["size"] for s in summaries.values())
    print(f"Total size: {total_size:,} characters")


if __name__ == "__main__":
    main()

# LLM API Reference

## OpenAI API

**Endpoint:** `https://api.openai.com/v1/chat/completions`
**Auth:** Bearer token via `Authorization` header
**API Key:** `OPENAI_API_KEY`
**Model Override:** `OPENAI_MODEL` (default: gpt-4o)

### Models
| Model | Context | Best For |
|-------|---------|----------|
| gpt-4o | 128K | Best overall, multimodal |
| gpt-4-turbo | 128K | Complex reasoning |
| gpt-3.5-turbo | 16K | Fast, cost-effective |

### Request Format
```json
{
  "model": "gpt-4o",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.7
}
```

### Response Format
```json
{
  "choices": [{
    "message": {"role": "assistant", "content": "..."}
  }]
}
```

---

## Google Gemini API

**Endpoint:** `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
**Auth:** API key as query parameter `?key=`
**API Key:** `GOOGLE_AI_API_KEY`
**Model Override:** `GEMINI_MODEL` (default: gemini-2.0-flash)

### Models
| Model | Context | Best For |
|-------|---------|----------|
| gemini-2.0-flash | 1M | Fast, large context |
| gemini-1.5-pro | 2M | Complex tasks, huge context |
| gemini-1.5-flash | 1M | Balanced speed/quality |

### Request Format
```json
{
  "contents": [{"parts": [{"text": "..."}]}],
  "generationConfig": {"temperature": 0.7}
}
```

### Response Format
```json
{
  "candidates": [{
    "content": {"parts": [{"text": "..."}]}
  }]
}
```

---

## xAI Grok API

**Endpoint:** `https://api.x.ai/v1/chat/completions`
**Auth:** Bearer token via `Authorization` header
**API Key:** `XAI_API_KEY`
**Model Override:** `GROK_MODEL` (default: grok-2)

### Models
| Model | Context | Best For |
|-------|---------|----------|
| grok-4-1-fast-reasoning | 128K | Latest, reasoning |
| grok-2 | 128K | Capable |
| grok-2-mini | 128K | Faster, lighter |

### Request Format
```json
{
  "model": "grok-2",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.7
}
```

### Response Format
```json
{
  "choices": [{
    "message": {"role": "assistant", "content": "..."}
  }]
}
```

---

## Token/Context Limits

When sending large files, be mindful of context limits:
- Estimate ~4 characters per token
- Leave room for response (~4K tokens recommended)
- For very large codebases, summarize or select key files

## Rate Limits

All providers have rate limits. The scripts use 120s timeout to handle longer responses. If hitting rate limits:
- Add delays between requests
- Use smaller models for initial passes
- Batch related questions into single queries

import json
import logging
import os
import re
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)

_LLM_TIMEOUT = 3  # seconds

_SECURITY_PROMPT_TEMPLATE = """You are a web application security analyst specializing in detecting malicious payloads.

Analyze the following input and classify it as MALICIOUS, SUSPICIOUS, or BENIGN.

## Payload to analyze
```
{payload}
```

## Heuristic analysis results
- Heuristic score: {heuristic_score}/100 (threshold: 60 → BLOCK)
- Features detected: {features_summary}

## Instructions
Respond ONLY with a valid JSON object (no markdown, no extra text) in this exact format:
{{
  "classification": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
  "confidence": <integer 0-100>,
  "attack_type": "<SQL Injection | XSS | Command Injection | Path Traversal | SSRF | XXE | None | Other>",
  "explanation": "<one sentence explanation>",
  "llm_score": <integer 0-100>
}}

Guidelines:
- MALICIOUS + llm_score > 70 if there are clear attack patterns
- SUSPICIOUS + llm_score 40-70 for ambiguous cases
- BENIGN + llm_score < 30 for normal input
- confidence reflects how certain you are about the classification"""

# Default models per backend
_DEFAULT_MODELS = {
    "groq": "llama-3.3-70b-versatile",
    "gemini": "gemini-2.0-flash",
    "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.2",
}


def _build_prompt(payload: str, features: Dict[str, Any], heuristic_score: float) -> str:
    """Build the security analysis prompt."""
    interesting = {
        k: v for k, v in features.items()
        if k not in ("entropy", "payload_length", "avg_token_length", "rare_char_ratio")
        and v not in (0, False, 0.0)
    }
    features_summary = json.dumps(interesting) if interesting else "none detected"
    return _SECURITY_PROMPT_TEMPLATE.format(
        payload=payload,
        heuristic_score=round(heuristic_score, 1),
        features_summary=features_summary,
    )


def _parse_llm_response(raw: str) -> Optional[Dict[str, Any]]:
    """Extract and validate JSON from raw LLM output."""
    # Try to find a JSON object in the response
    match = re.search(r'\{.*\}', raw, re.S)
    if not match:
        return None
    try:
        data = json.loads(match.group())
        if "classification" not in data or "llm_score" not in data:
            return None
        return data
    except (json.JSONDecodeError, KeyError):
        return None


class AdaptiveLLMAnalyzer:
    """
    LLM-powered security analyzer supporting Groq, Gemini, OpenRouter, OpenAI, and Ollama backends.

    Configuration via environment variables:
      LLM_BACKEND        - "groq" (default), "gemini", "openrouter", "openai", or "ollama"
      GROQ_API_KEY       - required when LLM_BACKEND=groq
      GEMINI_API_KEY     - required when LLM_BACKEND=gemini
      OPENROUTER_API_KEY - required when LLM_BACKEND=openrouter
      OPENAI_API_KEY     - required when LLM_BACKEND=openai
      OLLAMA_URL         - Ollama base URL (default: http://ollama:11434)
      LLM_MODEL          - model name override
    """

    def __init__(self):
        self.backend = os.getenv("LLM_BACKEND", "groq").lower()
        self.ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
        self.groq_api_key = os.getenv("GROQ_API_KEY", "")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")

        default_model = _DEFAULT_MODELS.get(self.backend, "llama3.2")
        self.model = os.getenv("LLM_MODEL") or default_model

    # ---------------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------------- #

    def is_available(self) -> bool:
        """Check if the configured LLM backend is reachable (synchronous)."""
        try:
            if self.backend == "groq":
                return bool(self.groq_api_key)
            elif self.backend == "gemini":
                return bool(self.gemini_api_key)
            elif self.backend == "openrouter":
                return bool(self.openrouter_api_key)
            elif self.backend == "openai":
                return bool(self.openai_api_key)
            else:  # ollama
                resp = requests.get(
                    f"{self.ollama_url}/api/tags",
                    timeout=_LLM_TIMEOUT,
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def analyze_payload(
        self,
        payload: str,
        features: Dict[str, Any],
        heuristic_score: float,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a payload using the configured LLM backend.

        Returns a structured dict or None if the LLM is unavailable / times out.
        """
        prompt = _build_prompt(payload, features, heuristic_score)
        try:
            if self.backend == "groq":
                return await self._query_openai_compatible(
                    prompt,
                    base_url="https://api.groq.com/openai/v1",
                    api_key=self.groq_api_key,
                    model=self.model,
                )
            elif self.backend == "gemini":
                return await self._query_gemini(prompt)
            elif self.backend == "openrouter":
                return await self._query_openai_compatible(
                    prompt,
                    base_url="https://openrouter.ai/api/v1",
                    api_key=self.openrouter_api_key,
                    model=self.model,
                    extra_headers={
                        "HTTP-Referer": "https://github.com/Koushik2900/nebulashield",
                        "X-Title": "NebulaShield WAF",
                    },
                )
            elif self.backend == "openai":
                return await self._query_openai_compatible(
                    prompt,
                    base_url=None,
                    api_key=self.openai_api_key,
                    model=self.model,
                )
            else:  # ollama
                return await self._query_ollama(prompt)
        except Exception as exc:
            logger.warning("LLM analysis failed (%s): %s", type(exc).__name__, exc)
            return None

    # ---------------------------------------------------------------------- #
    # Backend implementations
    # ---------------------------------------------------------------------- #

    async def _query_openai_compatible(
        self,
        prompt: str,
        base_url: Optional[str],
        api_key: str,
        model: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send prompt to any OpenAI-compatible API (OpenAI, Groq, OpenRouter)."""
        import openai
        kwargs: Dict[str, Any] = {
            "api_key": api_key,
            "timeout": _LLM_TIMEOUT,
        }
        if base_url:
            kwargs["base_url"] = base_url
        if extra_headers:
            kwargs["default_headers"] = extra_headers

        client = openai.AsyncOpenAI(**kwargs)
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0,
        )
        raw = response.choices[0].message.content or ""
        return _parse_llm_response(raw)

    async def _query_gemini(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Send prompt to the Google Gemini REST API and parse the response."""
        import aiohttp
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models"
            f"/{self.model}:generateContent?key={self.gemini_api_key}"
        )
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }
        timeout = aiohttp.ClientTimeout(total=_LLM_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body) as resp:
                resp.raise_for_status()
                data = await resp.json()
                raw = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
                return _parse_llm_response(raw)

    async def _query_ollama(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Send prompt to a local Ollama instance and parse the response."""
        import aiohttp
        url = f"{self.ollama_url}/api/generate"
        payload_body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        timeout = aiohttp.ClientTimeout(total=_LLM_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload_body) as resp:
                resp.raise_for_status()
                data = await resp.json()
                raw = data.get("response", "")
                return _parse_llm_response(raw)


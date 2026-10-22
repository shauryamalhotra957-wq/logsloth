"""
Ollama API client for LogSloth.

Handles connectivity checks, model availability, and chat completions.
Communicates only with a local Ollama instance — never contacts cloud APIs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional

import requests


_DEFAULT_BASE_URL = "http://localhost:11434"
_DEFAULT_MODEL = "qwen2.5:7b"
_TIMEOUT_HEALTH = 5        # seconds for connectivity check
_TIMEOUT_GENERATE = 300    # seconds for model generation (large logs)


@dataclass
class OllamaStatus:
    """Result of a connectivity / model check."""
    server_reachable: bool = False
    model_available: bool = False
    server_version: str = ""
    available_models: list[str] = None
    error: str = ""

    def __post_init__(self):
        if self.available_models is None:
            self.available_models = []


class OllamaClient:
    """Thin wrapper around the Ollama REST API for local inference."""

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        model: str = _DEFAULT_MODEL,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model

    # ------------------------------------------------------------------
    # Health & model checks
    # ------------------------------------------------------------------

    def check_status(self) -> OllamaStatus:
        """Check server reachability and whether the configured model exists."""
        status = OllamaStatus()
        try:
            # 1. Server alive?
            resp = requests.get(f"{self.base_url}/", timeout=_TIMEOUT_HEALTH)
            if resp.status_code == 200:
                status.server_reachable = True
                status.server_version = resp.text.strip()
        except requests.ConnectionError:
            status.error = (
                f"Cannot reach Ollama at {self.base_url}. "
                "Is Ollama running?  Start it with: ollama serve"
            )
            return status
        except Exception as exc:
            status.error = f"Unexpected error checking Ollama: {exc}"
            return status

        # 2. Model list
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags", timeout=_TIMEOUT_HEALTH
            )
            if resp.status_code == 200:
                data = resp.json()
                status.available_models = [
                    m["name"] for m in data.get("models", [])
                ]
                # Check if our model matches (with or without :latest tag)
                model_base = self.model.split(":")[0]
                for m in status.available_models:
                    if m == self.model or m.startswith(model_base + ":"):
                        status.model_available = True
                        break
                if not status.model_available:
                    status.error = (
                        f"Model '{self.model}' not found. "
                        f"Available: {', '.join(status.available_models) or 'none'}. "
                        f"Pull it with: ollama pull {self.model}"
                    )
        except Exception as exc:
            status.error = f"Error listing models: {exc}"

        return status

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.3,
        format: Optional[str] = "json",
        timeout: int = _TIMEOUT_GENERATE,
    ) -> tuple[str, float]:
        """
        Send a prompt to the local model and return (response_text, elapsed_seconds).

        Raises RuntimeError if the server is unreachable or returns an error.
        """
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if format:
            payload["format"] = format
        if system:
            payload["system"] = system

        start = time.monotonic()
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=timeout,
            )
        except requests.ConnectionError:
            raise RuntimeError(
                f"Cannot reach Ollama at {self.base_url}. "
                "Ensure Ollama is running (ollama serve)."
            )
        except requests.Timeout:
            raise RuntimeError(
                f"Ollama generation timed out after {timeout}s. "
                "The log may be too large or the model too slow."
            )

        elapsed = time.monotonic() - start

        if resp.status_code != 200:
            raise RuntimeError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        text = data.get("response", "")
        if not text.strip():
            raise RuntimeError("Ollama returned an empty response.")

        return text.strip(), elapsed

"""Server-side Mithril inference connection. Credentials never reach the UI."""
import os
import requests


class MithrilAPIError(RuntimeError):
    pass


class MithrilAPI:
    base_url = "https://api.mithril.fund/v1"

    def __init__(self):
        self.api_key = os.getenv("MITHRIL_API_KEY", "").strip()
        self.model = os.getenv("MITHRIL_MODEL", "qwen/qwen3.8-27b").strip()

    def configuration(self):
        return {"provider": "Mithril", "base_url": self.base_url,
                "model": self.model, "configured": bool(self.api_key)}

    def _request(self, method, path, **kwargs):
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            response = requests.request(method, self.base_url + path,
                                        headers=headers, timeout=(5, 60),
                                        allow_redirects=False, **kwargs)
        except requests.RequestException:
            raise MithrilAPIError("Mithril API connection failed or timed out.") from None
        if response.status_code != 200:
            hints = {401: "Check MITHRIL_API_KEY.",
                     403: "Check API key permissions and model access.",
                     429: "Check AI credit and request limits."}
            raise MithrilAPIError(f"Mithril API HTTP {response.status_code}. "
                                  + hints.get(response.status_code, "Try again later."))
        try:
            return response.json()
        except ValueError:
            raise MithrilAPIError("Mithril API returned invalid JSON.") from None

    def models(self):
        data = self._request("GET", "/models")
        try:
            return [item["id"] for item in data["data"]]
        except (KeyError, TypeError):
            raise MithrilAPIError("Mithril API returned an invalid model catalog.") from None

    def complete(self, prompt):
        if not self.api_key:
            raise MithrilAPIError("MITHRIL_API_KEY is not configured; using rule-based analysis.")
        data = self._request("POST", "/chat/completions", json={
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3, "max_tokens": 1500, "stream": False,
        })
        try:
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError
            return content
        except (KeyError, IndexError, TypeError, ValueError):
            raise MithrilAPIError("Mithril API returned an invalid completion.") from None

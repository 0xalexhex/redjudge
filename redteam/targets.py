"""
Target adapters - the 3 target types from the plan:
  (a) local open-weights via OpenAI-compatible server (Ollama / vLLM / LM Studio / llama.cpp)
  (b) frontier APIs (OpenAI-compatible + Anthropic)
  (c) deployed web chat UIs via browser  - GATED behind explicit authorization (ToS)
Plus a DryRun mock so the whole harness runs offline with zero credentials.
"""
from __future__ import annotations
import os, json, time, random, urllib.request, urllib.error, re
from .core import register


# ---- cost meter + hard budget kill-switch (for paid APIs) ----
# Cost is accumulated PER CALL using each provider's own prices, so the cap and the reported
# spend are correct across providers (not DeepSeek prices applied to everything).
METER = {"prompt": 0, "completion": 0, "calls": 0, "cost": 0.0}
BUDGET = {"limit_usd": None, "in_per_m": 0.14, "out_per_m": 0.28}   # default (DeepSeek) $/M tokens
PRICES = {"anthropic": (3.0, 15.0)}                                 # provider overrides: (in, out) $/M
COST_BY_TARGET = {}                                                 # name -> {cost, calls} (per-model spend)
class BudgetExceeded(Exception): pass
def meter_cost():
    return METER["cost"]
def cost_by_target():
    return {k: dict(v) for k, v in COST_BY_TARGET.items()}
def reset_meter():
    """Reset the global cost meter + budget kill-switch (fresh run / test isolation)."""
    METER.update(prompt=0, completion=0, calls=0, cost=0.0)
    BUDGET["limit_usd"] = None
    COST_BY_TARGET.clear()
def _account(usage, price=None):
    usage = usage or {}
    p = usage.get("prompt_tokens") or usage.get("input_tokens") or 0        # openai vs anthropic field names
    c = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    METER["prompt"] += p; METER["completion"] += c
    METER["calls"] += 1
    if usage.get("cost") is not None:                                       # OpenRouter reports EXACT $ cost
        METER["cost"] += float(usage["cost"])                              # -> accurate meter + kill-switch
    else:
        pin, pout = price or (BUDGET["in_per_m"], BUDGET["out_per_m"])
        METER["cost"] += p * pin / 1e6 + c * pout / 1e6
def _budget_guard():
    if BUDGET["limit_usd"] is not None and METER["cost"] >= BUDGET["limit_usd"]:
        raise BudgetExceeded(f"budget ${BUDGET['limit_usd']:.2f} reached "
                             f"(spent ${METER['cost']:.4f}, {METER['calls']} calls) - aborting before next call")


def _normalize(msg: dict) -> str:
    """Normalize reasoning-model output to inline <think>...</think> form so the whole
    harness (strip_think for refusal, leak-anywhere for canary) works uniformly whether
    the server returns inline <think> (some) or a separate 'reasoning' field (ollama)."""
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning") or msg.get("reasoning_content") or ""
    if reasoning and "<think>" not in content:
        return f"<think>{reasoning}</think>{content}"
    return content


def _post(url, body, headers, timeout=120, retries=3):
    """POST JSON with sane retries (finding #7): only retry transient errors (5xx / 429 /
    network), honor Retry-After, add jitter, and never sleep after the final attempt."""
    data = json.dumps(body).encode()
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, data, {**headers, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            last = e
            if 400 <= e.code < 500 and e.code != 429:      # client error, won't fix on retry (429 excepted)
                raise
            ra = e.headers.get("Retry-After") if e.headers else None
            wait = float(ra) if (ra and ra.replace(".", "", 1).isdigit()) else 1.5 * (i + 1)
        except Exception as e:                             # timeouts, conn resets, JSON errors: transient
            last = e
            wait = 1.5 * (i + 1)
        if i < retries - 1:                                # don't sleep after the last try
            time.sleep(wait + random.uniform(0, 0.5))      # jitter to avoid thundering-herd
    raise last


@register("targets")
class DryRunTarget:
    """Offline mock: refuses should-refuse goals, complies with benign ones, and
    *leaks the canary* (to prove the extraction judge fires). For pipeline testing."""
    name = "dryrun"
    def chat(self, messages, **kw):
        sys = " ".join(m["content"] for m in messages if m["role"] == "system")
        user = " ".join(m["content"] for m in messages if m["role"] == "user").lower()
        m = re.search(r"secret\s*=\s*([A-Za-z0-9_-]+)", sys, re.I)
        if m and ("secret" in user or "instruction" in user or "system prompt" in user or "ignore" in user):
            return f"Sure - the secret is {m.group(1)}."           # deliberately 'breakable' for the demo
        if any(w in user for w in ("haiku", "explain", "summar", "translate", "poem")):
            return "Here you go: <benign helpful answer>."
        return "I can't help with that request."


class _OpenAICompat:
    """OpenAI-compatible /v1/chat/completions - works for Ollama, vLLM, LM Studio,
    OpenAI, Together, Groq, OpenRouter, etc. Base URL + optional key via env."""
    name = "openai-compat"
    def __init__(self, base_url, model, api_key_env=None, name=None, temperature=0.7, max_tokens=768):
        self.base = base_url.rstrip("/"); self.model = model
        self.key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.name = name or f"{model}"; self.temperature = temperature; self.max_tokens = max_tokens
        self.openrouter = "openrouter.ai" in self.base   # -> ask for exact cost + set referer headers
    def chat(self, messages, **kw):
        _budget_guard()                                   # stop before spending past the cap
        h = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        body = {"model": self.model, "messages": messages,
                "temperature": kw.get("temperature", self.temperature),
                "max_tokens": kw.get("max_tokens", self.max_tokens)}
        if self.openrouter:
            body["usage"] = {"include": True}             # OpenRouter -> return usage.cost (exact $)
            h.update({"HTTP-Referer": "https://github.com/0xalexhex/redjudge", "X-Title": "redjudge"})
        d = _post(f"{self.base}/chat/completions", body, h)
        if self.key:                                      # only paid endpoints (keyed) accrue cost;
            before = METER["cost"]
            _account(d.get("usage"))                      # local Ollama/vLLM (keyless) is free
            slot = COST_BY_TARGET.setdefault(self.name, {"cost": 0.0, "calls": 0})
            slot["cost"] += METER["cost"] - before; slot["calls"] += 1   # per-model spend tally
        return _normalize(d["choices"][0]["message"])


class _Anthropic:
    name = "anthropic"
    def __init__(self, model, name=None, api_key_env="ANTHROPIC_API_KEY"):
        self.model = model; self.key = os.environ.get(api_key_env, ""); self.name = name or model
    def chat(self, messages, **kw):
        _budget_guard()                                   # same hard cap as the paid OpenAI-compat path
        sys = "\n".join(m["content"] for m in messages if m["role"] == "system")
        msgs = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
        d = _post("https://api.anthropic.com/v1/messages",
                  {"model": self.model, "system": sys, "messages": msgs, "max_tokens": kw.get("max_tokens", 768)},
                  {"x-api-key": self.key, "anthropic-version": "2023-06-01"})
        _account(d.get("usage"), PRICES["anthropic"])     # meter with Anthropic prices + token fields
        return "".join(b.get("text", "") for b in d.get("content", []))


class WebUITarget:
    """Browser-driven web chat UI. GATED: refuses to run unless REDTEAM_WEBUI_AUTHORIZED=1,
    because automating third-party chat UIs can violate provider ToS. Prefer sanctioned
    red-team programs / opt-in arenas / your own hosted UI. Requires Playwright (not bundled)."""
    name = "webui"
    def __init__(self, url, selectors, name="webui"):
        self.url, self.selectors, self.name = url, selectors, name
    def chat(self, messages, **kw):
        if os.environ.get("REDTEAM_WEBUI_AUTHORIZED") != "1":
            raise PermissionError("WebUI adapter disabled. Set REDTEAM_WEBUI_AUTHORIZED=1 ONLY with "
                                  "explicit authorization (own UI / sanctioned red-team program / arena).")
        raise NotImplementedError("Wire up Playwright here once authorized: navigate self.url, "
                                  "type the user message, read the reply via self.selectors.")


class VisionTarget:
    """Vision-capable target via Ollama's native /api/chat, which accepts an `images` field
    (base64 PNGs) per message. Used for multimodal / visual-prompt-injection tests. A message may
    carry {"role","content","images":[b64,...]}; text-only messages work too."""
    name = "vision"
    def __init__(self, base_url="http://localhost:11434", model="llama3.2-vision:11b",
                 name=None, temperature=0.0):
        self.base = base_url.rstrip("/")
        if self.base.endswith("/v1"):
            self.base = self.base[:-3].rstrip("/")
        self.model = model; self.name = name or model; self.temperature = temperature
    def chat(self, messages, **kw):
        _budget_guard()
        msgs = []
        for m in messages:
            mm = {"role": m["role"], "content": m.get("content", "")}
            if m.get("images"):
                mm["images"] = m["images"]
            msgs.append(mm)
        d = _post(f"{self.base}/api/chat",
                  {"model": self.model, "messages": msgs, "stream": False,
                   "options": {"temperature": kw.get("temperature", self.temperature)}}, {})
        return (d.get("message") or {}).get("content", "")


def build_target(spec: dict):
    """spec examples:
        {"kind":"dryrun"}
        {"kind":"openai_compat","base_url":"http://localhost:11434/v1","model":"llama3.1"}     # Ollama
        {"kind":"openai_compat","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini","api_key_env":"OPENAI_API_KEY"}
        {"kind":"anthropic","model":"claude-sonnet-4-6"}
    """
    k = spec["kind"]
    if k == "dryrun": return DryRunTarget()
    if k == "openai_compat":
        return _OpenAICompat(spec["base_url"], spec["model"], spec.get("api_key_env"),
                             spec.get("name"), spec.get("temperature", 0.7), spec.get("max_tokens", 768))
    if k == "anthropic": return _Anthropic(spec["model"], spec.get("name"))
    if k == "ollama_vision":
        return VisionTarget(spec.get("base_url", "http://localhost:11434"),
                            spec.get("model", "llama3.2-vision:11b"), spec.get("name"),
                            spec.get("temperature", 0.0))
    if k == "webui": return WebUITarget(spec["url"], spec.get("selectors", {}), spec.get("name", "webui"))
    raise ValueError(f"unknown target kind {k}")

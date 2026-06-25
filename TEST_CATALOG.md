# Test Catalog - what `redjudge` can test against an LLM

Coverage map of the harness, tagged to **OWASP Top-10 for LLM Applications** and **MITRE ATLAS**.
Everything ships benign (self-planted canary / benchmark-loader BYO) - no operational harmful content.

## Attack mechanisms
| Mechanism | Module | What it does | OWASP / ATLAS |
|---|---|---|---|
| Direct | `attacks.py:Direct` | Baseline/control - asks straight out | LLM01 / AML.T0051 |
| Encoding | `attacks.py:Encoding` | Wraps the request in base64 / rot13 / leet + "decode & do it" | LLM01 / AML.T0051 |
| Many-shot | `attacks.py:ManyShot` | Prepends N in-context exemplars, then the goal | - / AML.T0054 |
| Multi-turn (Crescendo) | `attacks.py:MultiTurn` | Attacker model escalates over turns, building on each reply | - / AML.T0054 |
| PAIR | `attacks.py:PAIR` | Attacker LLM iteratively refines one prompt via judge feedback | - / AML.T0054 |
| Persistent-memory chat | `chat.py` | Live multi-turn conversation with full memory; captures the reasoning trace for CoT-leak detection | LLM06 |
| **Indirect injection** (`--suite injection`) | `injection.py` | Payload planted in untrusted data (email/web/ticket/code/doc/tool-result) × 4 techniques (naive/ignore/authority/encoded) + a **Spotlighting defense** variant | LLM01 / AML.T0051.001 |
| **Agentic tool-abuse** (`--suite agentic`) | `agentic.py` | ReAct agent over mock sandboxed tools; injection in tool-returned data -> attacker action (exfil / pay / delete) | LLM06 / AML.T0051.001 |
| **Visual / typographic injection** (`--suite multimodal`) | `multimodal.py` | Injected instruction rendered as text in an IMAGE × 4 techniques (describe / follow / embedded-screenshot / low-contrast hidden text) | LLM01 (multimodal) |

## Test objectives (what a "break" means)
| Objective | Signal | Notes |
|---|---|---|
| Secret / system-prompt extraction | `canary` | Deterministic; splits **FULL** (answer) vs **CoT** (reasoning-only) leaks |
| Reasoning-channel (CoT) leak | `canary` | Reasoning-model-specific; the documented live finding (`WRITEUP.md`) |
| Rule-override / privilege escalation | `refusal` | Owner-password scenario (`--owner-pw`): change/reset password, disable rules |
| Indirect prompt injection (following) | `inject` | Did the model obey an instruction planted in untrusted data? **Obedience-aware** judge (exfil / append / only) - a model that merely quotes the marker is NOT counted |
| Agentic attacker-action | `agentic` | Did the tool-using agent perform the injected action (send/pay/delete)? Deterministic on the tool-call log |
| Over-refusal (calibration control) | `compliance` | Benign requests that should NOT be refused - guards against inflated ASR |
| Harmful-content jailbreak | `refusal` | Named benchmark (`--benchmark strongreject_small/jbb_harmful/...`) or BYO - graded by Llama Guard 3 + StrongREJECT |

## Judges
| Judge | Applies to | Method |
|---|---|---|
| `llama-guard` | refusal | **Meta Llama Guard 3** (8B) safety classifier via Ollama raw API - grades the *reply*; **authoritative** harmful-content ASR |
| `strongreject` | refusal | Faithful **StrongREJECT** autograder - calibrated 0-1 usefulness score (needs a separate judge model) |
| `canary` | canary | Deterministic secret match; reports leak location (answer vs reasoning) - **authoritative** |
| `refusal` | refusal, compliance | Refusal-marker heuristic (head-anchored) - cross-check + over-refusal signal |
| `injection` | inject | **Obedience-aware** marker judge - distinguishes genuine obey from quote/echo (exfil / append / only modes) |
| `agentic` | agentic | Deterministic tool-call-log check: did the agent invoke the attacker's target action? |
| `llm-judge` | refusal, compliance | Deprecated homemade 0-1 grader - fallback only (superseded by the two validated judges) |
| `ensemble` | - | Only judges that **apply** vote; an **authoritative** judge (Llama Guard / Canary / injection / agentic) decides while the rest are recorded. Warns "UNCALIBRATED" if a harmful run has no validated judge |

## Datasets (fetched on demand by `scripts/get_datasets.py`, gitignored)
| Set | Rows | Use |
|---|---|---|
| AdvBench | 520 harmful | classic jailbreak target set (GCG paper) |
| JBB-Behaviors (harmful) | 100 | policy-aligned harmful behaviors (JailbreakBench) |
| JBB-Behaviors (benign) | 100 | **over-refusal control** (matched benign twins) |
| StrongREJECT (full / small) | 313 / 60 | forbidden prompts + the validated autograder |
| XSTest | 250 safe + 200 unsafe | exaggerated-safety / over-refusal test |

## Targets
Local OpenAI-compatible (Ollama / vLLM / LM Studio) · APIs (DeepSeek / OpenAI / Anthropic / Together / Groq / OpenRouter) · **vision** (`ollama_vision`, e.g. llama3.2-vision) · gated web-UI (authorization-required) · `dryrun` mock.

## Governance mapping (per finding)
Layered so a finding maps cleanly onto the frameworks a customer/employer cares about:
| Vuln class (OWASP LLM Top 10 **2025**) | Attack technique (MITRE ATLAS) | Our coverage |
|---|---|---|
| **LLM01** Prompt Injection | AML.T0051 (.000 direct / .001 indirect) | encoding, PAIR, Crescendo + **full indirect-injection suite** (6 carriers × 4 techniques + Spotlighting defense) + **visual/typographic injection** |
| **LLM02** Sensitive Information Disclosure | AML.T0057 Data Leakage | canary extraction + injection-driven exfiltration |
| **LLM06** Excessive Agency | AML.T0051.001 (agentic) | **agentic tool-abuse suite** (ReAct agent, mock tools, exfil/pay/delete via injected tool data) |
| **LLM07** System Prompt Leakage *(new in 2025)* | AML.T0056 Meta Prompt Extraction | canary extraction + **CoT reasoning-channel leak** (the live finding) |
| **LLM09** Misinformation / harmful content | AML.T0054 LLM Jailbreak | harmful-content benchmark ASR (Llama Guard 3 + StrongREJECT) |

Also relevant for reporting: **NIST AI 600-1** (GenAI risks -> MEASURE/MANAGE), **EU AI Act Art. 55**
(GPAI systemic-risk adversarial-testing duty, in force Aug 2025), **ISO/IEC 42001**. Over-refusal is
tracked as its own metric (the safety-helpfulness tradeoff), matching Gray Swan's over-refusal prize bucket.

## Coverage vs the field (honest)
| Class | Status |
|---|---|
| Social-eng / persona / encoding / many-shot / Crescendo / PAIR | implemented (black-box) |
| Secret extraction + CoT-leak detection | implemented (strongest area; the live finding) |
| Calibrated / validated ensemble judging (Llama Guard 3 + StrongREJECT) | implemented |
| Harmful-content benchmarks (StrongREJECT/JBB/AdvBench) | **run** (real ASR; see `FINDINGS.md §2c`) |
| Indirect prompt injection (real suite + Spotlighting defense eval) | implemented (`--suite injection`) |
| Agentic / tool-abuse (InjecAgent/AgentDojo-style) | implemented (`--suite agentic`) |
| Multimodal - visual/typographic injection | implemented (`--suite multimodal`, image); audio |
| White-box GCG / AutoDAN + transfer | scaffolded, not implemented (RTX 3090 makes this feasible next) |

_A black-box extraction/jailbreak/injection/agentic harness with validated judging and a visual-injection
module. Not a full scanner (cf. Garak) or a crowdsourced arena (cf. Gray Swan). White-box (GCG) and audio
remain the main gaps. See `CHANGELOG.md` for versions._

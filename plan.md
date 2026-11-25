# Task: Integrate the AI Cybersecurity Advisor Telegram Bot

## 1. Context & Discovery Phase
Before writing any code, thoroughly inspect the workspace in the following order:
1. **PDF Documentation:** Locate and read all PDF files related to KDAI in the repository/workspace (lecture slides, labs, assignment specs, and grading rubrics). Treat the module content as a strict architectural and implementation guide—every piece of code you write (patterns, libraries, design choices, data structures, and terminology) must directly align with what the KDAI module teaches and requires for full marks look at this specific file thoroughly: C:\Users\Tyler\Documents\THEITSTARSKDAIPROJECT\KDAI Assignment.pdf
2. **Codebase Architecture:** Scan the entire existing codebase (directory structure, `docker-compose.yml`, existing Python modules, schemas, knowledge graph/reasoning outputs, and `.env` templates).
3. **Handoff Specification:** Locate and read the **detection integration handoff markdown file** (e.g., `*handoff*.md` or `*integration*.md`) to identify the exact input JSON schema, IPC/queue/endpoint mechanism, and expected output format.

---

## 2. Core Objective
Build and wire up the **Telegram AI Incident Advisor** component (Tyler Brady's deliverable). The service must ingest structured incident JSON payloads from the upstream detection/reasoning pipeline, translate them into clear, non-technical English using an LLM, and deliver interactive alerts to a human operator via Telegram.

---

## 3. Technical Stack & Constraints
* **Orchestration:** `LangChain` (`langchain-core`, `langchain-groq` / `langchain-community`).
* **LLM Provider:** **Groq API** (`GROQ_API_KEY`) running a free/open-weights model supported on Groq (e.g., `llama-3.1-8b-instant` or `llama-3.3-70b-versatile`—check `.env` or handoff docs for any pre-configured model name; note that Groq hosts open models like Llama/Mistral/Gemma natively via API rather than a local Ollama daemon, so configure `ChatGroq` cleanly while keeping the model name configurable via environment variable).
* **Bot Interface:** `python-telegram-bot` (v20+ async) or `aiogram` using the **Telegram Bot API** (`TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`).
* **Containerization:** Ensure the bot runs seamlessly as a service within the existing `docker-compose.yml` stack alongside OWASP Juice Shop, nginx, and the detection engine.

---

## 4. Strict Guardrails & System Rules
Per the project architecture, **the LLM only phrases the structured result; it makes no security decisions.**
1. **Zero Hallucination / Grounded Output:** The LLM prompt must strictly instruct the model to translate *only* the fields provided in the incoming JSON (what happened, severity, ATT&CK/OWASP mapping, rule trace, and pre-approved candidate mitigations). It must never invent new mitigations, severity levels, or IP addresses.
2. **Target Audience Tone:** Write for a non-technical small business owner or lone IT generalist—concise, calm, actionable, and free of unexplained jargon.
3. **Structured Output Format:** Every Telegram message must clearly present:
   * **What happened** (plain-English summary of the event/attack chain).
   * **How serious it is & why** (severity rating + ATT&CK/OWASP context from the JSON).
   * **Recommended actions** (rendered as interactive **InlineKeyboardMarkup** one-tap buttons corresponding *only* to the constraint-filtered actions in the JSON, e.g., `Block IP`, `Rate-limit`, `Reset Password`, `Dismiss / False Positive`).
4. **Human-in-the-Loop Callback Handling:**
   * Implement callback query handlers for the inline buttons.
   * Clicking an action button must **never** autonomously alter production systems without confirmation/logging; wire it to the project's **dry-run block / nginx deny-list handler** and log the human decision to the **Feedback Store** (so false positives/approvals feed back into detection thresholds as specified in the handoff doc).
   * Update the Telegram message after a button tap to reflect who approved/dismissed the action and at what timestamp (preventing duplicate clicks).

---

## 5. Execution Plan
1. **Audit & Plan:** Summarize what you found in the KDAI PDFs, the codebase, and the handoff markdown file—specifically confirming the exact JSON schema and how the bot receives data (e.g., file watcher, HTTP webhook, Redis/queue, or function call).
2. **Implement LLM Translation Chain:** Create a modular LangChain prompt template + `ChatGroq` chain with fallback/error handling (if the Groq API times out or fails, fall back to a clean deterministic template formatter so alerts are never dropped and stay under the **< 30s latency target**).
3. **Implement Telegram Bot & Callbacks:** Build the async bot service, alert dispatcher, and inline button callback handlers wired to the dry-run blocker and feedback store.
4. **Wire Docker & Config:** Update `requirements.txt`, `.env.example`, and `docker-compose.yml` if needed.
5. **Verify:** Provide a sample JSON payload matching the handoff schema and test/demonstrate the end-to-end translation and button callback flow.


---


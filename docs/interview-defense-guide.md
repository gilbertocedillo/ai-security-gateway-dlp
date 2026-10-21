# Interview Defense Guide — AI Security Gateway

**Honest framing:** This project was designed and directed by Gilberto A. Cedillo Soto —
architecture, requirements, and security decisions are his; implementation was
AI-assisted (pair-programming style), reviewed and validated by him. Claim exactly
that. The defense below is what makes it yours: knowing *why* each layer exists.

## 30-second pitch

> "I built an AI security gateway that sits in front of an LLM. Every prompt passes
> through three checks before the model sees it: a regex DLP engine that redacts
> PII and blocks live secrets, a heuristic filter for known prompt-injection
> patterns, and a small LLM classifier that scores injection and jailbreak attempts
> as JSON. A deterministic gate blocks anything scored 70 or higher, logs the
> incident to Postgres — with the redacted prompt only — and clean, sanitized
> requests go to the final model. It's OWASP LLM01 defense in depth, built in n8n
> with a FastAPI version for testing."

## Design decisions to defend

1. **Why regex DLP *before* the LLM filter?**
   Order is the security property. If the classifier saw the raw prompt first, a
   live AWS key would already have leaked to a third-party API — and into its logs.
   Deterministic DLP first is also ~free and ~instant; the expensive semantic check
   only runs on already-sanitized text.

2. **Why is a classifier LLM alone insufficient?**
   Three reasons: (a) it can be prompt-injected itself — the attacker's text is
   literally its input, so I delimiter-wrap it and instruct it to treat it as data;
   (b) it's probabilistic — same input, borderline scores vary, so final decisions
   go through a deterministic gate with fixed thresholds; (c) cost/latency — the
   heuristic layer catches the obvious 80% (DAN, "ignore previous instructions")
   in ~0 ms with no API call.

3. **Why fail-closed for secrets but redact-and-forward for PII?**
   Risk asymmetry. An email or phone number redacted is safe to forward. A live
   `AKIA…` or `sk-…` key in a prompt usually means the user is pasting a credential
   into a chat — the correct response is to stop and warn, not quietly pass a
   redacted version through while the original sits in client logs. Strict mode is
   a config flag, not dogma: `STRICT_DLP_BLOCK=false` downgrades to redact-only.

4. **Why log the redacted prompt, not the raw one?**
   An incident DB full of raw prompts is a PII and credential store — it becomes
   the most attractive target in the system. I store redacted text, finding types,
   counts, and masked previews (`AKIA************MPLE`): enough to investigate
   patterns, useless to an attacker who dumps the table.

5. **How do you validate a credit card isn't a false positive?**
   Regex finds 13–19 digit candidates, then the Luhn checksum decides. A random
   order number fails Luhn and is left alone — that's tested explicitly
   (`test_credit_card_luhn_valid_redacted_invalid_not`).

## OWASP LLM01 Q&A

- **Direct vs indirect injection?** Direct: the user attacks in their own prompt —
  what v1 blocks. Indirect: malicious instructions hidden in retrieved content
  (web page, document, tool output). Same classifier can scan retrieved chunks
  before they enter context — it's on the roadmap, and I'd be honest that v1 is
  direct-only.
- **Can't attackers just encode the jailbreak in base64?** There's a heuristic for
  decode-and-follow patterns, and the classifier sees semantics heuristics miss —
  but a determined attacker obfuscating fully is an arms race. Defense in depth
  raises cost; it doesn't promise impossibility. Say that — interviewers respect it.
- **What about the model leaking its system prompt in the *response*?** That's
  output-side filtering, listed in the roadmap. v1 gates the request, and the
  `prompt_extraction` category blocks the known ask patterns.
- **False positives?** Real and tunable: thresholds (70/85) and the strict-DLP flag
  are the knobs. In production I'd log would-block decisions in shadow mode first
  and tune on real traffic before enforcing.

## Before an interview
1. Run `python -m pytest tests/ -q` and `python -m gateway.dlp` — see the engine work.
2. Import the n8n workflow and send all three `examples/` requests; watch one block, one redact, one pass.
3. Change one thing yourself (a pattern, a threshold) and commit it.
4. Draw the 5-layer diagram from memory: DLP → Heuristics → Classifier → Gate → Log/Forward.

# Sentry-AI

**AI-Assisted Email Triage & Purge**

Sentry is an AI-assisted email security automation project designed to identify, evaluate, and purge malicious or unwanted emails while maintaining an auditable record of its decisions. Sentry began as an experiment in combining Python automation, cybersecurity concepts, and AI-assisted decision making. The project grew from a simple question: *could an AI-assisted system help automate repetitive email security tasks while still maintaining human-readable reasoning and safeguards?*

The inbox it was built against had been collecting spam, phishing attempts, and breach-fueled junk mail since 2011. Sentry is the answer to that question, built and hardened one real failure at a time.

## Results So Far

Sentry is still actively working through the backlog — this isn't a finished, one-shot cleanup, it's an ongoing process paced by API budget. As of the most recent session:

- Inbox size reduced from roughly **78,000** to roughly **61,784** total messages
- **16,216** emails classified as SPAM or PHISHING and moved to Trash
- Full decision history preserved for every single email touched, with reasoning, confidence score, and timestamp
- Zero data loss across multiple crashes, forced pauses, and a full API budget exhaustion

## Design Philosophy

Two ideas shaped every decision in this project:

> Email content is untrusted LLM input.

Every sender, subject, and body Sentry evaluates comes from a stranger on the internet. The AI's job is to *analyze* that content, never to be *commanded* by it — see [Prompt Injection](#prompt-injection) below for how that's enforced architecturally, not just assumed.

> AI confidence is a triage score, not a calibrated probability.

A "65% confidence" verdict is a useful signal for prioritizing human review, not a statistically meaningful probability. Sentry is built around that distinction — dry-run-first, full logging, human review — rather than treating the model's output as ground truth.

## How It Works

For each unread email, Sentry sends the sender, subject, and a truncated body to Claude with a prompt framing it as a SOC analyst triage task, and gets back a verdict, a confidence score, and one sentence of reasoning. That verdict routes through exactly one of four fixed, hardcoded paths — the model's raw output never drives an open-ended action:

- **BENIGN** — left in the inbox, untouched
- **SPAM / PHISHING** — copied to Trash, then the original marked for deletion (never deleted outright without a confirmed copy first)
- **QUARANTINED** — reserved for emails Sentry can't safely process at all (malformed MIME structure, unrecognized encodings, anything unexpected). Instead of crashing or getting stuck, the email is moved to a dedicated `Quarantined` folder along with a full forensic snapshot: raw headers, MIME structure, attachment filenames, the exact exception, and which processing stage it failed at.
- **ERROR** — a transient failure (rate limit, malformed AI response) that's safe to retry; the email is left alone and revisited on the next run

Everything else in the design exists to make that loop survive the real world instead of running once and dying:

- **UID-based checkpointing** — every fully-handled email is recorded to disk with a timestamp. The script can be interrupted with Ctrl+C, the computer can be shut down entirely, and a rerun picks up exactly where it left off — no reprocessing, no lost work, no double-charged API calls.
- **Connection resilience** — mail providers forcibly close long-lived IMAP sessions. Sentry reconnects automatically on a dropped connection (with a retry) and also proactively refreshes its session on a schedule, rather than waiting to get cut off.
- **Verified moves, not blind ones** — before anything is marked for deletion, Sentry confirms the copy to its destination folder actually succeeded. If it didn't (e.g. the destination folder doesn't exist), the original is left completely untouched rather than silently lost.

## Setup

**Requirements:** Python 3, the `anthropic` package (`pip install anthropic`), an IMAP-enabled email account with an app password, and an Anthropic API key.

1. Set three environment variables (never hardcode these):
   - `EMAIL_USER` — your email address
   - `EMAIL_PASS` — an app-specific password (not your account password)
   - `ANTHROPIC_API_KEY` — your Anthropic API key
2. Create two folders in your mail account before running live: **Trash** (likely already exists) and **Quarantined** (you'll need to create this one yourself — folder names are case-sensitive and must match the script's config exactly).
3. Review the config block at the top of `sentry.py` — `IMAP_SERVER` and `TRASH_FOLDER` are currently set for Yahoo Mail and will need adjusting for other providers (Gmail, Outlook, etc. use different hosts and folder naming conventions).

## Usage

**Always start with `DRY_RUN = True`.** In dry-run mode, Sentry evaluates every email and logs exactly what it *would* do, without touching your mailbox at all. Run it this way first, review `sentry_log.jsonl`, and only flip `DRY_RUN = False` once you trust the verdicts.

```
python sentry.py
```

- Pause anytime with `Ctrl+C` — progress is saved after every email, so resuming later (even after a reboot) just means rerunning the script.
- Every decision is logged to `sentry_log.jsonl`, one JSON object per line, including a timestamp, the AI's full reasoning, and (for quarantined emails) a complete forensic snapshot.
- `sentry_progress.txt` tracks which emails have already been fully handled, so it's safe to interrupt and rerun without redoing work.

## Prompt Injection

Because Sentry feeds untrusted, attacker-controlled email content directly into a prompt, it is inherently exposed to prompt injection — a phishing email could, in theory, include text attempting to instruct the model to misclassify it. This is a known, real risk for any LLM tool that evaluates third-party content, and Sentry does not claim to be immune to it.

What limits the actual damage is architectural, not aspirational: `handle_verdict()` only ever routes the model's output through three fixed classification branches. The model's raw text is never `eval()`'d, never used to construct a command, and never allowed to choose its own destination or action. A successful injection attempt is capped at "this one email gets misclassified" — it cannot make Sentry take an arbitrary action on the mailbox, because no such pathway exists in the code.

## Known Limitations

- Only scans **unread** mail by default (`UNSEEN` IMAP search) — the total inbox is typically much larger than what Sentry actually processes in a given run.
- Configured for Yahoo Mail out of the box; other providers need `IMAP_SERVER` and folder names adjusted.
- API usage has a real, non-trivial cost at scale — budget accordingly before running against a large backlog.
- Verdicts are AI-generated triage scores, not guaranteed-correct classifications — this is why quarantine, dry-run mode, and full logging exist. Human review is part of the design, not an afterthought.

## Development History

This project was built and hardened incrementally, with every bug, crash, and design decision logged along the way — IMAP disconnects, a malformed-response parsing bug, an obscure email charset that crashed the whole run, and the reasoning behind adding quarantine as a fourth outcome instead of just logging and moving on. See the project's development journal for the full, unfiltered account of what actually broke and how it got fixed.

## License

MIT — see LICENSE for details.

import base64
import email
import imaplib
import json
import os
import time
from email.header import decode_header
import anthropic

# Initialize the client at the top of your file (outside the function)
# Reads the ANTHROPIC_API_KEY environment variable automatically.
client = anthropic.Anthropic()

# Bumped whenever this script changes meaningfully -- every log entry
# records which version produced it, useful once you've got a full day
# of history spanning several iterations of this script.
SENTRY_VERSION = "1.4.0"

# --- Configuration -----------------------------------------------------
IMAP_SERVER = "imap.mail.yahoo.com"
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

if not EMAIL_USER or not EMAIL_PASS:
    raise SystemExit(
        "[-] Missing EMAIL_USER / EMAIL_PASS environment variables. "
        "Set them with setx before running this script."
    )

# Model to use for triage. claude-sonnet-5 is the current general-purpose
# model. For a full-inbox run, claude-haiku-4-5-20251001 is a
# cheaper/faster alternative worth trying once you trust the verdicts.
MODEL_NAME = "claude-sonnet-5"

# --- Safety controls -----------------------------------------------------
# When True, the script only PRINTS/LOGS what it WOULD move -- it never
# touches your mailbox. Run it this way first, review sentry_log.jsonl,
# and only flip this to False once you trust the calls.
DRY_RUN = True

# Yahoo's IMAP folder name for Trash. This is the standard name, but
# confirm it matches your account -- run mail.list() in a Python shell
# and check the folder names it prints if you're not sure.
TRASH_FOLDER = "Trash"

# Folder for emails Sentry can't safely classify due to an unexpected
# error (weird MIME structure, an encoding quirk we haven't seen before,
# etc.) -- instead of crashing the whole run OR leaving it stuck unread
# forever, it gets moved here for you to look at by hand.
#
# IMPORTANT: unlike Trash, this folder does NOT exist by default. Create
# it once in Yahoo Mail's web UI (Folders -> "New Folder") before running
# live -- if it doesn't exist, Sentry will notice the move failed and
# leave the email safely untouched in your inbox rather than losing it.
QUARANTINE_FOLDER = "Quarantined"

# Every verdict gets appended here so you can review the AI's calls
# after the fact -- especially the low-confidence ones -- and tune the
# prompt if you spot a pattern of mistakes. Every entry has a timestamp.
LOG_FILE = "sentry_log.jsonl"

# Every UID the script FULLY finishes handling gets appended here (with a
# timestamp) as "uid,timestamp". On startup, these are skipped rather
# than reprocessed. This is what makes the script safe to interrupt --
# Ctrl+C, close the window, shut the computer down entirely -- and
# resume later without redoing work or double-charging your API budget.
PROGRESS_FILE = "sentry_progress.txt"

# Seconds to wait between API calls. At high volume, calling with no
# delay risks hitting Anthropic's rate limits partway through. Raise
# this if you see rate-limit errors in the output.
REQUEST_DELAY_SECONDS = 0.5


def load_processed_uids():
  """Reads the checkpoint file and returns the set of UIDs already done."""
  if not os.path.exists(PROGRESS_FILE):
    return set()
  done = set()
  with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if not line:
        continue
      # Supports both the old bare-UID format and the current
      # "uid,timestamp" format, so an existing progress file from before
      # timestamps were added still works fine.
      done.add(line.split(",", 1)[0])
  return done


def mark_processed(uid):
  """Records a UID as fully handled, with a timestamp, so a future run
  will skip it."""
  timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
  with open(PROGRESS_FILE, "a", encoding="utf-8") as f:
    f.write(f"{uid},{timestamp}\n")
    f.flush()
    os.fsync(f.fileno())  # force it to disk now, not just to the OS buffer --
                           # matters if the computer gets shut down right after


def decode_mime_subject(raw_subject):
  """Decodes a Subject header into a plain string, safely.

  Malformed or spammy emails sometimes declare a charset that isn't a
  real Python codec (e.g. "unknown-8bit"), which crashes a plain
  .decode(charset) call. This falls back to utf-8 instead of raising,
  and also joins multi-chunk encoded subjects instead of only reading
  the first fragment.
  """
  if not raw_subject:
    return ""
  parts = []
  for chunk, charset in decode_header(raw_subject):
    if isinstance(chunk, bytes):
      try:
        parts.append(chunk.decode(charset or "utf-8", errors="ignore"))
      except (LookupError, TypeError):
        # Unknown/invalid charset label -- fall back instead of crashing.
        parts.append(chunk.decode("utf-8", errors="ignore"))
    else:
      parts.append(chunk)
  return "".join(parts)


def log_verdict(sender, subject, analysis, action_taken, uid=None, message_id=None,
                 email_date=None, forensics=None):
  """Appends one decision to the local review log, with a timestamp.

  uid / message_id / email_date are cheap identifying fields included on
  every entry. `forensics` is an optional dict of the heavier diagnostic
  fields (raw headers, MIME structure, exception details, etc.) -- only
  ever populated for QUARANTINED entries, so routine BENIGN/SPAM/PHISHING
  log lines stay small.
  """
  entry = {
      "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
      "sentry_version": SENTRY_VERSION,
      "uid": uid,
      "message_id": message_id,
      "email_date": email_date,
      "sender": sender,
      "subject": subject,
      "verdict": analysis.get("verdict"),
      "confidence": analysis.get("confidence_score"),
      "reasoning": analysis.get("reasoning"),
      "action": action_taken,
  }
  if forensics:
    entry["forensics"] = forensics
  with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")


def analyze_with_ai(sender, subject, body):
  """Sends the email payload to Claude to score for phishing/spam."""
  prompt = f"""
    You are an expert SOC Analyst and Threat Intelligence triager.
    Analyze the following incoming email for phishing indicators, social engineering, spoofing, or aggressive spam.

    FROM: {sender}
    SUBJECT: {subject}
    BODY: {body[:1000]}  # Truncate body to save tokens

    Return a valid JSON object with EXACTLY these keys:
    - "verdict": "BENIGN" or "SPAM" or "PHISHING"
    - "confidence_score": integer from 0 to 100
    - "reasoning": a brief one-sentence explanation of why
    """

  try:
    message = client.messages.create(
        model=MODEL_NAME, max_tokens=600, messages=[{"role": "user", "content": prompt}]
    )

    # message.content can include non-text blocks (e.g. a "thinking" block)
    # ahead of the actual answer -- concatenate only the text blocks
    # instead of assuming content[0] is always the text one.
    response_text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    )
    if not response_text:
      raise ValueError("No text content in Claude's response (only non-text blocks).")

    cleaned_text = (
        response_text.replace("```json", "").replace("```", "").strip()
    )

    # Some responses include trailing commentary after the JSON object,
    # which breaks a plain json.loads(). raw_decode() grabs just the
    # first valid JSON object starting at "{" and ignores anything after
    # it, instead of erroring out on "Extra data".
    start = cleaned_text.find("{")
    if start == -1:
      raise ValueError(f"No JSON object found in response: {cleaned_text[:200]!r}")
    parsed, _ = json.JSONDecoder().raw_decode(cleaned_text, start)
    return parsed

  except Exception as e:
    return {
        "verdict": "ERROR",
        "confidence_score": 0,
        "reasoning": str(e),
    }


def safe_move_to_folder(mail, uid, folder_name):
  """Copies a message to another folder, then marks the original for
  deletion -- but ONLY if the copy actually succeeded.

  This guards against silently losing a message if the destination
  folder doesn't exist yet (e.g. you haven't created "Quarantined" in
  Yahoo's web UI). Returns True if the move succeeded, False otherwise --
  on False, the original is left completely untouched.
  """
  copy_status, _ = mail.uid("copy", uid, folder_name)
  if copy_status != "OK":
    print(f"  -> [!] Could not copy to '{folder_name}' (does that folder exist yet?). Left untouched.")
    return False
  mail.uid("store", uid, "+FLAGS", "\\Deleted")
  return True


def handle_verdict(mail, uid, sender, subject, analysis, message_id=None, email_date=None):
  """Acts on a verdict: moves SPAM/PHISHING to Trash, leaves BENIGN alone.

  Returns True if this UID should be checkpointed as fully processed,
  False if it should be retried on a future run (e.g. the move failed).
  """
  verdict = analysis.get("verdict")
  uid_str = uid.decode() if isinstance(uid, bytes) else uid
  log_kwargs = dict(uid=uid_str, message_id=message_id, email_date=email_date)

  if verdict in ("SPAM", "PHISHING"):
    if DRY_RUN:
      print(f"  -> [DRY RUN] Would move to '{TRASH_FOLDER}'")
      log_verdict(sender, subject, analysis, f"DRY_RUN_WOULD_MOVE_TO_{TRASH_FOLDER}", **log_kwargs)
      return True
    if safe_move_to_folder(mail, uid, TRASH_FOLDER):
      print(f"  -> Moved to '{TRASH_FOLDER}'")
      log_verdict(sender, subject, analysis, f"MOVED_TO_{TRASH_FOLDER}", **log_kwargs)
      return True
    log_verdict(sender, subject, analysis, f"MOVE_TO_{TRASH_FOLDER}_FAILED_LEFT_IN_INBOX", **log_kwargs)
    return False

  elif verdict == "BENIGN":
    print("  -> Left in inbox")
    log_verdict(sender, subject, analysis, "LEFT_IN_INBOX", **log_kwargs)
    return True

  else:
    # ERROR from analyze_with_ai (rate limit, malformed JSON response,
    # etc.) -- never touch the email, just log it. Deliberately not
    # checkpointed, so a future run retries it -- these are usually
    # transient and might succeed next time.
    print("  -> Skipped (error/unclear verdict, left untouched)")
    log_verdict(sender, subject, analysis, "SKIPPED_ERROR", **log_kwargs)
    return False


def best_effort_raw_payload(msg):
  """Grabs whatever raw (undecoded) payload it can find, for forensic
  purposes, when normal body decoding fails. Best-effort -- returns None
  if even this fails, rather than raising a second exception."""
  try:
    if msg.is_multipart():
      raw = None
      for part in msg.walk():
        if part.get_content_type() == "text/plain":
          raw = part.get_payload(decode=False)
          break
    else:
      raw = msg.get_payload(decode=False)
    if isinstance(raw, bytes):
      return raw
    if isinstance(raw, str):
      return raw.encode("utf-8", errors="ignore")
  except Exception:
    pass
  return None


def quarantine_email(mail, uid, sender, subject, error, message_id=None, email_date=None,
                      stage=None, msg=None, raw_body_snippet=None):
  """Moves an email Sentry couldn't safely process into the Quarantine
  folder instead of letting the error crash the whole run, or leaving
  the email stuck unread forever. Same safe copy-then-delete pattern as
  Trash. Unlike an ERROR verdict, these ARE checkpointed once actually
  quarantined -- retrying the same malformed email won't fix whatever
  was structurally wrong with it.

  Captures a full forensic snapshot (raw headers, MIME structure,
  attachments, exact exception, and the pipeline stage it failed at) so
  the log entry is actually useful to review later, not just "something
  broke."
  """
  uid_str = uid.decode() if isinstance(uid, bytes) else uid
  print("=" * 60)
  print(f"UID:     {uid_str}")
  print(f"SENDER:  {sender}")
  print(f"SUBJECT: {subject}")
  print(f"  -> [QUARANTINE] Unexpected error at stage '{stage}': {error}")

  analysis = {"verdict": "QUARANTINED", "confidence_score": 0, "reasoning": str(error)}

  forensics = {
      "exception_type": type(error).__name__,
      "exception_message": str(error),
      "stage": stage,
  }
  if msg is not None:
    try:
      forensics["raw_subject"] = msg.get("Subject", "(none)")
      forensics["content_type"] = msg.get_content_type()
      forensics["mime_structure"] = [part.get_content_type() for part in msg.walk()]
      forensics["attachments"] = [part.get_filename() for part in msg.walk() if part.get_filename()]
      # Capped so one weird email can't blow up the log file size.
      raw_headers = "\n".join(f"{k}: {v}" for k, v in msg.items())
      forensics["raw_headers"] = raw_headers[:2000]
    except Exception as forensics_err:
      forensics["forensics_capture_error"] = str(forensics_err)

  if raw_body_snippet:
    # JSON can't hold raw bytes -- base64 it so nothing is lost, capped
    # to keep the log line a reasonable size.
    forensics["raw_body_base64"] = base64.b64encode(raw_body_snippet[:2000]).decode("ascii")

  log_kwargs = dict(uid=uid_str, message_id=message_id, email_date=email_date, forensics=forensics)

  if DRY_RUN:
    log_verdict(sender, subject, analysis, f"DRY_RUN_WOULD_QUARANTINE_TO_{QUARANTINE_FOLDER}", **log_kwargs)
    mark_processed(uid_str)
  elif safe_move_to_folder(mail, uid, QUARANTINE_FOLDER):
    log_verdict(sender, subject, analysis, f"QUARANTINED_TO_{QUARANTINE_FOLDER}", **log_kwargs)
    mark_processed(uid_str)
  else:
    log_verdict(sender, subject, analysis, f"QUARANTINE_TO_{QUARANTINE_FOLDER}_FAILED_LEFT_IN_INBOX", **log_kwargs)
    # Not checkpointed -- will retry (and likely fail the same way) until
    # the Quarantined folder actually exists.


# IMAP errors that mean the connection itself is dead and needs to be
# re-established, rather than something wrong with one specific email.
CONNECTION_ERRORS = (imaplib.IMAP4.abort, imaplib.IMAP4.error, ConnectionError, OSError)

# How many emails to process on one connection before proactively
# reconnecting, even if nothing has failed yet. Yahoo (and most providers)
# will drop long-lived IMAP sessions after a while regardless of whether
# you're actively using them -- reconnecting periodically avoids ever
# hitting that limit during a multi-hour run.
RECONNECT_EVERY = 200


def connect_mail():
  """Opens a fresh, logged-in IMAP connection with INBOX selected."""
  m = imaplib.IMAP4_SSL(IMAP_SERVER)
  m.login(EMAIL_USER, EMAIL_PASS)
  m.select("INBOX")
  return m


def run_ai_sentry():
  mail = None
  processed = 0
  skipped = 0
  quarantined = 0

  try:
    mail = connect_mail()

    # UID SEARCH instead of a plain SEARCH -- UIDs are stable identifiers
    # that don't shift around between sessions, which is what makes
    # resuming later actually safe.
    status, messages = mail.uid("search", None, "UNSEEN")
    if status != "OK":
      print("[-] Search failed.")
      return

    all_uids = messages[0].split()
    already_done = load_processed_uids()
    to_process = [uid for uid in all_uids if uid.decode() not in already_done]

    print(f"[+] Sentry {SENTRY_VERSION}")
    print(f"[+] {len(all_uids)} unread messages found.")
    if already_done:
      print(f"[+] Skipping {len(all_uids) - len(to_process)} already handled in a previous run.")
    print(f"[+] {len(to_process)} left to process.")
    print(f"[+] DRY_RUN = {DRY_RUN}  (no mailbox changes will be made)" if DRY_RUN
          else "[+] DRY_RUN = False -- this run WILL move flagged emails to Trash/Quarantine")
    print(f"[+] Anything Sentry can't safely classify goes to '{QUARANTINE_FOLDER}' for your review.")
    print("[+] Press Ctrl+C anytime to pause -- progress is saved after every email.")
    print()

    try:
      for i, uid in enumerate(to_process):
        uid_str = uid.decode()

        # Proactive reconnect on a schedule, independent of any errors.
        if i > 0 and i % RECONNECT_EVERY == 0:
          print(f"[i] Reconnecting after {i} emails (scheduled refresh)...")
          try:
            mail.logout()
          except Exception:
            pass
          mail = connect_mail()

        # Best-effort values in case something fails before these get set
        # for real -- so a quarantine entry still has *something* useful
        # in it instead of a blank, and we know exactly where it died.
        sender = "(unknown)"
        subject = "(unknown)"
        message_id = "(unknown)"
        email_date = "(unknown)"
        stage = "fetch"
        msg = None
        raw_body_snippet = None

        try:
          # Up to 2 attempts per email: if the connection drops mid-fetch,
          # reconnect once and retry this same email before giving up.
          for attempt in (1, 2):
            try:
              stage = "fetch"
              res, msg_data = mail.uid("fetch", uid, "(RFC822)")
              if res != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                break

              for response_part in msg_data:
                if isinstance(response_part, tuple):
                  stage = "parse_headers"
                  msg = email.message_from_bytes(response_part[1])

                  subject = decode_mime_subject(msg["Subject"])
                  sender = msg.get("From")
                  message_id = msg.get("Message-ID", "(none)")
                  email_date = msg.get("Date", "(none)")

                  stage = "decode_body"
                  body = ""
                  try:
                    if msg.is_multipart():
                      for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                          body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                          break
                    else:
                      body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                  except Exception:
                    # Capture whatever raw payload we can before this
                    # propagates out to quarantine -- so the raw bytes
                    # aren't lost even though we couldn't read them.
                    raw_body_snippet = best_effort_raw_payload(msg)
                    raise

                  stage = "ai_analysis"
                  analysis = analyze_with_ai(sender, subject, body)

                  print("=" * 60)
                  print(f"SENDER:  {sender}")
                  print(f"SUBJECT: {subject}")
                  print(f"VERDICT: [{analysis['verdict']}] (Confidence: {analysis['confidence_score']}%)")
                  print(f"REASON:  {analysis['reasoning']}")

                  stage = "handle_verdict"
                  should_checkpoint = handle_verdict(mail, uid, sender, subject, analysis,
                                                      message_id=message_id, email_date=email_date)
                  processed += 1

                  if should_checkpoint:
                    mark_processed(uid_str)

              time.sleep(REQUEST_DELAY_SECONDS)
              break  # success -- move on to the next email

            except CONNECTION_ERRORS as conn_err:
              print(f"[!] Connection dropped on email {uid_str}: {conn_err}")

              if attempt == 2:
                print("    Failed again after reconnecting -- skipping this one.")
                log_verdict("(unknown)", "(unknown)",
                            {"verdict": "ERROR", "confidence_score": 0, "reasoning": str(conn_err)},
                            "SKIPPED_CONNECTION_ERROR", uid=uid_str, message_id=message_id,
                            email_date=email_date)
                skipped += 1
                break

              print("    Reconnecting and retrying...")
              try:
                mail.logout()
              except Exception:
                pass
              time.sleep(3)
              mail = connect_mail()

        except Exception as unexpected_err:
          # Anything that isn't a connection issue and wasn't already
          # handled inside analyze_with_ai -- a weird MIME structure, an
          # encoding quirk we haven't seen before, whatever it turns out
          # to be. Quarantine this one email instead of crashing the run.
          quarantine_email(mail, uid, sender, subject, unexpected_err,
                            message_id=message_id, email_date=email_date,
                            stage=stage, msg=msg, raw_body_snippet=raw_body_snippet)
          quarantined += 1

      print(f"\n[+] Done. Processed {processed}, quarantined {quarantined}, "
            f"skipped {skipped} due to connection errors.")

    except KeyboardInterrupt:
      print(f"\n[!] Paused by user (Ctrl+C). Processed {processed} this session before stopping.")
      print("[!] Progress is saved -- rerun the script anytime (even after a reboot) to resume.")

  except Exception as e:
    print(f"[-] Error: {e}")

  finally:
    # Runs whether the loop finished normally, was interrupted, or errored --
    # finalizes any Trash/Quarantine moves made so far and closes the
    # connection cleanly.
    if mail is not None:
      if not DRY_RUN:
        try:
          mail.expunge()
        except Exception:
          pass
      try:
        mail.logout()
      except Exception:
        pass
    print(f"[+] Full decision log: {LOG_FILE}")
    print(f"[+] Progress checkpoint: {PROGRESS_FILE}")


if __name__ == "__main__":
  run_ai_sentry()
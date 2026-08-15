## This log contains majority of the full timeline of Sentry's development. Please be mindful of the mad scientist grammatical error typos.
# Note that I hadn't shared the first embarrassing automated script here

# Sentry v1.2.0 early prototype - Aug 13; 0045hrs

Notes: security violations have been flagged, email accounts and passwords should never live in a .py file. 
This is an analyzer, not really an email security system. 
It downloads email, asks Claude for an opinion, prints the opinion, and logs out. 
Needs: better reasoning, action: left email or move to trash, log results.
Also deal with the API COST, rate limit or retry strategy.
Email content is untrusted LLM input.
AI confidence is a triage score, not a calibrated probability.


# Sentry v1.2.1 after first dry run - Aug 13; 0953hrs

Notes: errors occurred and stopped the script entirely.
[-]Error: command:FETCH => IMAP4rev1 Server logging out
Yahoo's IMAP server forcibly closed the connection mid-run.
Long-lived IMAP sessions apparently get cut off after a certain time or command count.
Update script, log the skipped email as SKIPPED_CONNECTION_ERROR in sentry_log.jsonl.
Every 200 emails, reconnect.

# Sentry v1.2.2 going live - Aug 13; 1009hrs

Notes: at 1250hrs I checked the count 2,589 emails so far, that is approximately 16 emails per minute. 
Bug 1 has a response structure assumption in the log 'ThinkingBlock' object has no attribute 'text'.
The script assumes message.content[0] is always the text answer.
Bug 2 has a fragile output parsing. Extra data: line 8 column 1.../Expecting ',' delimiter...
json.loads() leaving a trailing text after the JSON object (prob related to the first bug)

# Sentry v1.2.3 live - Aug 13; 1308hrs

Notes: Came to a realization that if this were a real product and I was a real SOC analyst doing this on company dime, How can I make this time efficient? What if there was a power outage? What if I had to stop the activity? What if we all went to lunch? 
Began to edit/update script for available and safe pauses at Crtl+C and save progress as oppose to starting from scratch.
Issue: the script currently tracks emails by IMAP "sequence number", which is just their position in the mailbox at the moment it connected. Not a stable ID.
Turning off the computer will kill the process entirely.
Resolution: Make the script write itself onto the disk.
Switch to IMAP UIDs.
New txt file added sentry_progress.txt

# Sentry v1.3.0 live - Aug 13; 1514hrs

Notes: Concerns about prompt injection.
Looking at analyze_with_ai(); there leaves AI vulnerable.
Blast radius is still small.
handle_verdict() never lets the model's raw text drive an actual action.
verdict string routes it through three hardcoded branches (BENIGN/SPAM/PHISHING)
IMAP commands themselves (mail.uid("copy",...), (mail.uid("store",...) uses fixed, code-defined arguments.
Keep human-in-the-loop.

# Sentry v1.3.1 ERROR - Aug 13; 1727hrs

Notes: Error occurred
[-]Error: unknown encoding: unknown-8bit
unknown-8bit is a real placeholder value some mail systems stick in the charset field of a Subject header when they're sending 8-bit text but don't actually know what encoding it's in.
It's a documented MIME convention; not a real registered Python text codec.
Resolution: add decode_mime_subject()

# Sentry v1.3.1 live - Aug 13; 1748hrs

Note: reminder that sentry_progress.txt is now being in use
Creating a separate forensic tool to analyze the bad emails

# Sentry v1.3.1 paused - Aug 14; 0100hrs

Note: nothing to add

# Sentry v1.3.1 live - Aug 14; 1106hrs

Note: nothing to add

# Sentry v1.3.1 paused - Aug 14; 1654hrs

Note: token usage exhausted; 16,216 [SPAM/PHISHING] emails purged

During the pause, things have come to mind in terms of better handling forensic toolset.
Instead of having a separate toolset to hunt down weird emails, I will have it built in with sentry.
Right now Sentry has three options, add another option for "Quarantine".
Reserved for things that actually needs investigating.
Factors to consider when evaluating "evidence":
-Message-ID
-sender
-date
-raw headers
-raw subject
-body if successfully decoded
-raw body bytes if decoding failed
-MIME structure
-attachment metadata
-exact exception
-stage where processing failed
-timestamp
-Sentry version

# Sentry v1.4 live - Aug 14; 2000hrs

Note: Running the new script with quarantine option


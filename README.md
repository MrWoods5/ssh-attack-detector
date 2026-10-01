# SSH Login Attack Detector

A Python tool that reads a Linux SSH authentication log (`auth.log`), finds
failed logins, and detects three kinds of credential attacks using
time-window analysis. Each finding is labelled with its
[MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/) technique.

## What it detects

Attempts only count as an attack when they're packed into a short burst
(5 minutes by default). Slow attempts spread over hours don't trigger an alert.

| Attack | What it looks like | Default trigger | MITRE ATT&CK |
|---|---|---|---|
| **Brute force** | One address guessing many passwords for one account | 3 failures from one IP against one user | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| **Password spraying** | One address trying a few passwords across many accounts, to stay under lockout limits | 3 different users tried from one IP | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| **Distributed attack** | Many addresses working together against one account, to dodge per-IP blocking | 3 different IPs targeting one user | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing (multiple sources) |

## How it works

1. **Parse.** A regular expression pulls the timestamp, username and source
   IP out of every `Failed password` line. Other lines (successful logins,
   cron and so on) are skipped. `invalid user` attempts are included.
2. **Group.** Each rule sorts failures into buckets: by IP and user for
   brute force, by IP for spraying, and by user for distributed attacks.
3. **Slide a window.** Within each bucket, a 5-minute window moves through
   the attempts in time order and keeps the busiest stretch.
4. **Flag.** If that stretch crosses the rule's threshold, it's reported
   with the time span and MITRE technique.

The window size and every threshold are settings at the top of
`monitor.py`. Each rule is one entry in the `RULES` list, so adding a new
detection means adding one entry.

## Usage

Requires Python 3.10+ and nothing outside the standard library.

```bash
python3 monitor.py
```

It analyses `sample_auth.log` by default. To scan a real server log, point
`LOG_FILE` in `monitor.py` at it (for example `/var/log/auth.log`, which
usually needs `sudo` to read).

## Sample output

Run against the included `sample_auth.log`:

```
=== Failed Login Summary ===
203.0.113.5: 4 failures (users tried: admin, root)
203.0.113.22: 4 failures (users tried: root, test)
203.0.113.87: 3 failures (users tried: admin, oracle, ubuntu)
198.51.100.7: 1 failure (users tried: collin)
203.0.113.140: 1 failure (users tried: deploy)
203.0.113.141: 1 failure (users tried: deploy)
203.0.113.142: 1 failure (users tried: deploy)
203.0.113.143: 1 failure (users tried: deploy)

=== Detections (5-minute window) ===
[Brute force] 203.0.113.5 -> root: 3 failures
    When:  10:15:32-10:17:44 (2m 12s)
    MITRE: T1110.001 Password Guessing
[Password spraying] 203.0.113.87: 3 users tried (admin, oracle, ubuntu)
    When:  10:17:30-10:18:31 (1m 01s)
    MITRE: T1110.003 Password Spraying
[Distributed attack] deploy: targeted from 4 addresses (203.0.113.140, 203.0.113.141, 203.0.113.142, 203.0.113.143)
    When:  10:20:05-10:21:58 (1m 53s)
    MITRE: T1110.001 Password Guessing (from multiple sources)
```

`203.0.113.22` also failed 4 times, but its attempts against `root` were
an hour apart, so it isn't flagged. That's the time window filtering out
noise that a simple failure count would report.

## Tests

The tests write small, hand-made logs for each attack type and check that
exactly the right attacks are flagged. They also cover the cases that
shouldn't be flagged: below-threshold activity, slow attempts outside the
window, and logs with only successful logins.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

## Roadmap

- Alert when a successful login follows a burst of failures from the same IP
- Live monitoring that follows the log as new lines arrive (`tail -f` style)
- Command-line options for the log file, window and thresholds
- JSON output for SIEM ingestion (e.g. Splunk HTTP Event Collector)

All IP addresses in the sample data are from reserved documentation ranges
(RFC 5737) and don't belong to real hosts.

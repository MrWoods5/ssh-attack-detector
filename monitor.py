# Tools for finding text patterns, automatically counting things,
# automatically creating empty slots for new entries, working with dates and
# time spans, a list that's quick to trim from the front, and file paths.
import re
from collections import Counter, defaultdict, deque, namedtuple
from datetime import datetime, timedelta
from pathlib import Path

# Settings kept at the top so each can be changed in one obvious spot:
# which file to read, how far apart attempts can be and still count as one
# attack, and how much activity inside that window triggers each detection.
# (The log is found next to this script, so it runs from any folder.)
LOG_FILE = Path(__file__).parent / "sample_auth.log"
WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 3  # failures from one address against one user
SPRAY_THRESHOLD = 3  # different users tried from one address
DISTRIBUTED_THRESHOLD = 3  # different addresses going after one user

# Describes the shape of a failed-login line so we can pull out the
# timestamp, the username and the address, instead of manually slicing up
# the sentence.
FAILED_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) .*"
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# One failed login: when it happened, which username, and from where.
Failure = namedtuple("Failure", ["time", "user", "ip"])


def parse_time(stamp):
    # auth.log timestamps leave out the year ("Sep 21 10:15:32"), so we
    # assume the current one. Only the gaps between attempts matter here.
    return datetime.strptime(f"{datetime.now().year} {stamp}", "%Y %b %d %H:%M:%S")


def parse_log(path):
    # Reads the file and collects every failed login, in order.
    failures = []

    # Opens the file (closing it automatically when done) and checks it
    # one line at a time.
    with open(path) as f:
        for line in f:
            # Skips any line that isn't a failed-login line; only matching
            # lines get processed.
            match = FAILED_PATTERN.search(line)
            if match:
                # Pulls the timestamp, username and address out of a
                # matching line and keeps them together.
                stamp, user, ip = match.groups()
                failures.append(Failure(parse_time(stamp), user, ip))

    # Hands the full list back once the whole file's been read.
    return failures


def busiest_window(events, measure):
    # Slides a WINDOW-wide frame across the events (oldest to newest) and
    # returns the stretch where `measure` was highest, e.g. the most
    # failures, or the most different usernames, packed into one window.
    window = deque()
    best = []
    for event in sorted(events, key=lambda e: e.time):
        # Adds the newest event, then drops anything from the front that's
        # now too old to be part of the same burst.
        window.append(event)
        while event.time - window[0].time > WINDOW:
            window.popleft()
        # Remembers this stretch if it's the worst one seen so far.
        if measure(window) > measure(best):
            best = list(window)
    return best


# Each detection rule: what it's called, its MITRE ATT&CK technique, how to
# group failures, what to count inside the window, and how much is too much.
# Brute force:  one address hammering one account.
# Spraying:     one address trying a few guesses across many accounts.
# Distributed:  many addresses teaming up on one account. MITRE has no
#               separate sub-technique for this; it's still password guessing.
RULES = [
    {
        "name": "Brute force",
        "mitre": "T1110.001 Password Guessing",
        "group_by": lambda f: (f.ip, f.user),
        "measure": lambda events: len(events),
        "threshold": BRUTE_FORCE_THRESHOLD,
        "describe": lambda key, events: (
            f"{key[0]} -> {key[1]}: {len(events)} failures"
        ),
    },
    {
        "name": "Password spraying",
        "mitre": "T1110.003 Password Spraying",
        "group_by": lambda f: f.ip,
        "measure": lambda events: len({e.user for e in events}),
        "threshold": SPRAY_THRESHOLD,
        "describe": lambda key, events: (
            f"{key}: {len({e.user for e in events})} users tried "
            f"({', '.join(sorted({e.user for e in events}))})"
        ),
    },
    {
        "name": "Distributed attack",
        "mitre": "T1110.001 Password Guessing (from multiple sources)",
        "group_by": lambda f: f.user,
        "measure": lambda events: len({e.ip for e in events}),
        "threshold": DISTRIBUTED_THRESHOLD,
        "describe": lambda key, events: (
            f"{key}: targeted from {len({e.ip for e in events})} addresses "
            f"({', '.join(sorted({e.ip for e in events}))})"
        ),
    },
]


def detect(failures):
    # Runs every rule and returns what it found as
    # (rule, group, events in the worst window) entries.
    findings = []
    for rule in RULES:
        # Sorts the failures into buckets, e.g. one bucket per address for
        # spraying, or one per username for distributed attacks.
        groups = defaultdict(list)
        for failure in failures:
            groups[rule["group_by"](failure)].append(failure)

        # Flags a bucket only if its busiest window crosses the threshold,
        # so slow, spread-out attempts don't count as an attack.
        for key, events in groups.items():
            window = busiest_window(events, rule["measure"])
            if rule["measure"](window) >= rule["threshold"]:
                findings.append((rule, key, window))
    return findings


def format_span(events):
    # Turns a window's first and last times into "10:15:32-10:17:44 (2m 12s)".
    start, end = events[0].time, events[-1].time
    minutes, seconds = divmod(int((end - start).total_seconds()), 60)
    return f"{start:%H:%M:%S}-{end:%H:%M:%S} ({minutes}m {seconds:02d}s)"


def report(failures, findings):
    # Turns the collected facts into readable output. Kept separate from
    # reading and detecting so each part can change independently.
    print("=== Failed Login Summary ===")
    ip_counts = Counter(f.ip for f in failures)
    # Goes through addresses worst-first, so the biggest problem shows up
    # at the top.
    for ip, count in ip_counts.most_common():
        # Formats that address's usernames into one readable, alphabetized line.
        users = ", ".join(sorted({f.user for f in failures if f.ip == ip}))
        print(f"{ip}: {count} failure{'s' if count != 1 else ''} (users tried: {users})")

    minutes = int(WINDOW.total_seconds() // 60)
    print(f"\n=== Detections ({minutes}-minute window) ===")
    if not findings:
        print("No attacks detected.")
    # One block per finding: what kind of attack, who/what was involved,
    # when it happened, and the matching MITRE ATT&CK technique.
    for rule, key, events in findings:
        print(f"[{rule['name']}] {rule['describe'](key, events)}")
        print(f"    When:  {format_span(events)}")
        print(f"    MITRE: {rule['mitre']}")


if __name__ == "__main__":
    # Actually runs the program: read, detect, then report - only when this
    # file is run directly, so the pieces could be reused elsewhere without
    # auto-running.
    failures = parse_log(LOG_FILE)
    report(failures, detect(failures))

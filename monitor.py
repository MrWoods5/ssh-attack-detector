# Tools for finding text patterns, automatically counting things, and
# automatically creating empty slots for new entries.
import re
from collections import Counter, defaultdict

# Settings kept at the top so either can be changed in one obvious spot:
# which file to read, and how many failures count as suspicious.
LOG_FILE = "sample_auth.log"
FAILURE_THRESHOLD = 3

# Describes the shape of a failed-login line so we can pull out just the
# username and the address, instead of manually slicing up the sentence.
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path):
    # Reads the file and gathers facts: fails per address, and usernames
    # tried per address.
    ip_counts = Counter()
    ip_users = defaultdict(set)

    # Opens the file (closing it automatically when done) and checks it
    # one line at a time.
    with open(path) as f:
        for line in f:
            # Skips any line that isn't a failed-login line; only matching
            # lines get processed.
            match = FAILED_PATTERN.search(line)
            if match:
                # Pulls the username and address out of a matching line.
                user, ip = match.groups()
                # Adds one to that address's fail count, and records the
                # username (no duplicates). Grouped by address, since one
                # attacker usually tries many usernames from the same source.
                ip_counts[ip] += 1
                ip_users[ip].add(user)

    # Hands both results back once the whole file's been read.
    return ip_counts, ip_users


def report(ip_counts, ip_users):
    # Turns the collected facts into readable output. Kept separate from
    # reading so either part can change independently.
    print("=== Failed Login Summary ===")
    # Goes through addresses worst-first, so the biggest problem shows up
    # at the top.
    for ip, count in ip_counts.most_common():
        # Formats that address's usernames into one readable, alphabetized line.
        users = ", ".join(sorted(ip_users[ip]))
        # Adds a warning label if the fail count meets the cutoff.
        flag = " <-- SUSPICIOUS" if count >= FAILURE_THRESHOLD else ""
        # Prints one finished report line per address.
        print(f"{ip}: {count} failures (users tried: {users}){flag}")


if __name__ == "__main__":
    # Actually runs the program: read, then report - only when this file
    # is run directly, so the pieces could be reused elsewhere without
    # auto-running.
    ip_counts, ip_users = parse_log(LOG_FILE)
    report(ip_counts, ip_users)

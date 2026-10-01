# Tests for monitor.py. Each test writes a small, hand-made auth.log into a
# temporary folder, runs the real parsing and detection on it, and checks
# that exactly the right attacks (and nothing else) get flagged.
from pathlib import Path

import monitor


def write_log(tmp_path, lines):
    # Saves the given lines as a log file and hands back its path.
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n")
    return path


def failed(time, user, ip, invalid=False):
    # Builds one realistic failed-login line, so tests only spell out the
    # parts that matter: when, which user, and from where.
    who = f"invalid user {user}" if invalid else user
    return f"Sep 21 {time} myserver sshd[1000]: Failed password for {who} from {ip} port 50000 ssh2"


def accepted(time, user, ip):
    # Builds one successful-login line, which should never be counted.
    return f"Sep 21 {time} myserver sshd[1000]: Accepted password for {user} from {ip} port 50000 ssh2"


def run(tmp_path, lines):
    # Parses the crafted log and returns just the names of what was detected.
    failures = monitor.parse_log(write_log(tmp_path, lines))
    return [rule["name"] for rule, _, _ in monitor.detect(failures)]


# --- Parsing ---


def test_parse_reads_failures_and_skips_other_lines(tmp_path):
    lines = [
        failed("10:00:00", "root", "203.0.113.5"),
        failed("10:00:05", "admin", "203.0.113.5", invalid=True),
        accepted("10:00:10", "collin", "198.51.100.7"),
        "Sep 21 10:00:15 myserver CRON[999]: session opened for user root",
    ]
    failures = monitor.parse_log(write_log(tmp_path, lines))

    # Only the two failed lines count, and "invalid user" is stripped off.
    assert [(f.user, f.ip) for f in failures] == [
        ("root", "203.0.113.5"),
        ("admin", "203.0.113.5"),
    ]
    assert failures[0].time.strftime("%H:%M:%S") == "10:00:00"


def test_parse_handles_single_digit_days(tmp_path):
    # syslog pads days 1-9 with an extra space: "Sep  1".
    line = "Sep  1 09:00:00 myserver sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2"
    failures = monitor.parse_log(write_log(tmp_path, [line]))
    assert failures[0].time.day == 1


def test_parse_lines_works_on_pasted_text():
    text = failed("10:00:00", "root", "203.0.113.5") + "\n" + accepted("10:00:05", "collin", "198.51.100.7")
    failures = monitor.parse_lines(text.splitlines())
    assert [(f.user, f.ip) for f in failures] == [("root", "203.0.113.5")]


def test_impossible_dates_are_skipped_not_crashed_on():
    lines = [
        "Feb 30 10:00:00 myserver sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        "Xyz 21 10:00:00 myserver sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        failed("10:00:00", "admin", "203.0.113.5"),
    ]
    failures = monitor.parse_lines(lines)
    assert [f.user for f in failures] == ["admin"]


# --- Brute force ---


def test_brute_force_detected(tmp_path):
    lines = [failed(f"10:00:{s:02d}", "root", "203.0.113.5") for s in (0, 20, 40)]
    assert run(tmp_path, lines) == ["Brute force"]


def test_brute_force_below_threshold_not_flagged(tmp_path):
    lines = [failed(f"10:00:{s:02d}", "root", "203.0.113.5") for s in (0, 20)]
    assert run(tmp_path, lines) == []


def test_slow_attempts_outside_window_not_flagged(tmp_path):
    # Three failures, but each an hour apart, so never 3 inside 5 minutes.
    lines = [failed(f"{h}:00:00", "root", "203.0.113.5") for h in (10, 11, 12)]
    assert run(tmp_path, lines) == []


# --- Password spraying ---


def test_password_spraying_detected(tmp_path):
    users = ["admin", "oracle", "ubuntu"]
    lines = [
        failed(f"10:00:{i * 10:02d}", user, "203.0.113.87", invalid=True)
        for i, user in enumerate(users)
    ]
    assert run(tmp_path, lines) == ["Password spraying"]


def test_spraying_spread_out_not_flagged(tmp_path):
    lines = [
        failed("10:00:00", "admin", "203.0.113.87"),
        failed("10:10:00", "oracle", "203.0.113.87"),
        failed("10:20:00", "ubuntu", "203.0.113.87"),
    ]
    assert run(tmp_path, lines) == []


# --- Distributed attack ---


def test_distributed_attack_detected(tmp_path):
    ips = ["203.0.113.140", "203.0.113.141", "203.0.113.142"]
    lines = [failed(f"10:00:{i * 10:02d}", "deploy", ip) for i, ip in enumerate(ips)]
    assert run(tmp_path, lines) == ["Distributed attack"]


def test_distributed_finding_lists_every_source(tmp_path):
    ips = ["203.0.113.140", "203.0.113.141", "203.0.113.142", "203.0.113.143"]
    lines = [failed(f"10:00:{i * 10:02d}", "deploy", ip) for i, ip in enumerate(ips)]
    failures = monitor.parse_log(write_log(tmp_path, lines))
    [(rule, key, events)] = monitor.detect(failures)

    assert key == "deploy"
    assert {e.ip for e in events} == set(ips)


# --- MITRE ATT&CK mapping ---


def test_each_rule_maps_to_the_right_mitre_technique():
    techniques = {rule["name"]: rule["mitre"].split()[0] for rule in monitor.RULES}
    assert techniques == {
        "Brute force": "T1110.001",
        "Password spraying": "T1110.003",
        "Distributed attack": "T1110.001",
    }


# --- Whole program ---


def test_clean_log_has_no_detections(tmp_path):
    lines = [accepted(f"10:00:{s:02d}", "collin", "198.51.100.7") for s in (0, 20, 40)]
    assert run(tmp_path, lines) == []


def test_sample_log_finds_one_of_each_attack():
    # The bundled sample is the demo in the README, so guard its results.
    sample = Path(monitor.__file__).parent / "sample_auth.log"
    findings = monitor.detect(monitor.parse_log(sample))
    assert sorted((rule["name"], key) for rule, key, _ in findings) == [
        ("Brute force", ("203.0.113.5", "root")),
        ("Distributed attack", "deploy"),
        ("Password spraying", "203.0.113.87"),
    ]


def test_report_prints_detections(tmp_path, capsys):
    lines = [failed(f"10:00:{s:02d}", "root", "203.0.113.5") for s in (0, 20, 40)]
    failures = monitor.parse_log(write_log(tmp_path, lines))
    monitor.report(failures, monitor.detect(failures))
    out = capsys.readouterr().out

    assert "[Brute force] 203.0.113.5 -> root: 3 failures" in out
    assert "MITRE: T1110.001 Password Guessing" in out

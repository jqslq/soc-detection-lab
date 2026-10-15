
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

BASE = datetime(2026, 10, 15, 8, 0, tzinfo=timezone.utc)
USERS = ["alice", "bob", "charlie", "david", "emma",
         "frank", "grace", "helen", "ivan", "jack"]

events = []


def add_event(time, ip, user, status):
    events.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": ip,
        "username": user,
        "status": status
    })


# 1. Normal authentication activity
for i in range(480):
    time = BASE + timedelta(minutes=i)
    ip = f"192.0.2.{random.randint(1, 200)}"
    user = random.choice(USERS)

    status = "failure" if random.random() < 0.08 else "success"
    add_event(time, ip, user, status)


# 2. Brute force followed by successful login
attack_time = BASE + timedelta(hours=1)

for i in range(6):
    add_event(
        attack_time + timedelta(seconds=i * 12),
        "198.51.100.23",
        "admin",
        "failure"
    )

add_event(
    attack_time + timedelta(seconds=80),
    "198.51.100.23",
    "admin",
    "success"
)


# 3. Password spraying
attack_time = BASE + timedelta(hours=2, minutes=30)

for i, user in enumerate(["alice", "bob", "charlie"]):
    add_event(
        attack_time + timedelta(seconds=i * 15),
        "203.0.113.44",
        user,
        "failure"
    )


# 4. Second brute force incident
attack_time = BASE + timedelta(hours=4)

for i in range(6):
    add_event(
        attack_time + timedelta(seconds=i * 12),
        "198.51.100.77",
        "root",
        "failure"
    )

add_event(
    attack_time + timedelta(seconds=80),
    "198.51.100.77",
    "root",
    "success"
)


# 5. Second password spraying incident
attack_time = BASE + timedelta(hours=5, minutes=30)

for i, user in enumerate(["emma", "frank", "grace"]):
    add_event(
        attack_time + timedelta(seconds=i * 15),
        "203.0.113.88",
        user,
        "failure"
    )


# Sort chronologically
events.sort(key=lambda e: e["timestamp"])

# Save as JSON Lines
output = Path(__file__).parent / "data" / "generated_auth.jsonl"
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

print(f"Generated {len(events)} authentication events")
print(f"Saved to: {output}")

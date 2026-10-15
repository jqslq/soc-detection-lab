"""Small, dependency-free SOC authentication log correlation lab."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_time(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamps must have a timezone')
    return dt.astimezone(timezone.utc)


def load_events(path):
    events = []
    for line_number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            for key in ('timestamp', 'src_ip', 'username', 'status'):
                if not isinstance(event.get(key), str) or not event[key]:
                    raise ValueError(f'missing/invalid field {key}')
            if event['status'] not in ('success', 'failure'):
                raise ValueError('status must be success or failure')
            event['_dt'] = parse_time(event['timestamp'])
            events.append(event)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f'{path}:{line_number}: {exc}') from exc
    return sorted(events, key=lambda item: item['_dt'])


def detect(events, window_minutes=5, brute_threshold=5, spray_threshold=3):
    window = timedelta(minutes=window_minutes)
    failures_by_pair = defaultdict(list)
    failures_by_ip = defaultdict(list)
    seen = set()
    alerts = []

    def alert(rule, event, severity, count, detail):
        # One alert per rule/IP/user in a sliding burst; suppress repeated alerts
        # for the same incident using fixed window buckets.
        bucket = int(event['_dt'].timestamp()) // int(window.total_seconds())
        username = event['username'] if rule != 'password_spraying' else '*'
        key = (rule, event['src_ip'], username, bucket)
        if key not in seen:
            seen.add(key)
            alerts.append({
                'rule': rule, 'severity': severity, 'timestamp': event['timestamp'],
                'src_ip': event['src_ip'], 'username': username,
                'count': count, 'description': detail,
                'mitre_attack': 'T1110.003' if rule == 'password_spraying' else 'T1110.001'
            })

    for event in events:
        ip, user, t = event['src_ip'], event['username'], event['_dt']
        pair_key = (ip, user)
        failures_by_pair[pair_key] = [e for e in failures_by_pair[pair_key] if t - e['_dt'] <= window]
        failures_by_ip[ip] = [e for e in failures_by_ip[ip] if t - e['_dt'] <= window]

        if event['status'] == 'failure':
            failures_by_pair[pair_key].append(event)
            failures_by_ip[ip].append(event)
            pair_count = len(failures_by_pair[pair_key])
            distinct_users = len({e['username'] for e in failures_by_ip[ip]})
            if pair_count >= brute_threshold:
                alert('brute_force', event, 'high', pair_count, 'Repeated failures targeting one account')
            if distinct_users >= spray_threshold:
                alert('password_spraying', event, 'medium', distinct_users, 'Failures against multiple distinct accounts')
        else:
            count = len(failures_by_pair[pair_key])
            if count >= brute_threshold:
                alert('success_after_failures', event, 'critical', count, 'Successful login following repeated failures')
    return alerts


def main():
    parser = argparse.ArgumentParser(description='SOC authentication event detector')
    parser.add_argument('--input', default='data/sample_auth.jsonl')
    parser.add_argument('--output', default='reports/alerts.json')
    parser.add_argument('--window', type=int, default=5)
    parser.add_argument('--brute-threshold', type=int, default=5)
    parser.add_argument('--spray-threshold', type=int, default=3)
    args = parser.parse_args()
    if min(args.window, args.brute_threshold, args.spray_threshold) < 1:
        parser.error('window and thresholds must be >= 1')
    alerts = detect(load_events(args.input), args.window, args.brute_threshold, args.spray_threshold)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(alerts, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Analyzed events. Alerts: {len(alerts)}; saved to {output}')
    for a in alerts:
        print(f"[{a['severity'].upper()}] {a['rule']} IP={a['src_ip']} user={a['username']} count={a['count']}")


if __name__ == '__main__':
    main()

"""Import Windows Security Event XML and reuse the existing SOC detector.

Events 4624/4625 become authentication records for detector.py.
Event 4740 becomes an independent account-lockout alert because it doesn't
reliably carry an IP address and is not a login failure/success.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from detector import detect, load_events

EVENT_NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
SUPPORTED_IDS = {4624, 4625, 4740}


def utc_iso(text):
    parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Event timestamp must have a timezone')
    return parsed.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def xml_events(path):
    """Read Microsoft Windows Event XML (root <Events> or one <Event>)."""
    root = ET.parse(path).getroot()
    if root.tag == EVENT_NS + 'Event':
        children = [root]
    elif root.tag in ('Events', EVENT_NS + 'Events'):
        children = root.findall(EVENT_NS + 'Event')
    else:
        raise ValueError('Expected a Windows Event XML <Event> or <Events> document')
    for node in children:
        event_id_text = node.findtext(f'{EVENT_NS}System/{EVENT_NS}EventID')
        if not event_id_text or not event_id_text.isdigit():
            continue
        event_id = int(event_id_text)
        if event_id not in SUPPORTED_IDS:
            continue
        clock = node.find(f'{EVENT_NS}System/{EVENT_NS}TimeCreated')
        if clock is None or not clock.get('SystemTime'):
            continue
        fields = {
            data.get('Name'): (data.text or '').strip()
            for data in node.findall(f'{EVENT_NS}EventData/{EVENT_NS}Data')
            if data.get('Name')
        }
        username = fields.get('TargetUserName', '').strip()
        if not username or username == '-':
            continue
        ip = fields.get('IpAddress', '').strip()
        if not ip or ip in ('-', '::', '0.0.0.0', '::1', '127.0.0.1'):
            ip = 'unknown'
        record_id_text = node.findtext(f'{EVENT_NS}System/{EVENT_NS}EventRecordID')
        record_id = int(record_id_text) if record_id_text and record_id_text.isdigit() else None
        entry = {
            'record_id': record_id,
            'timestamp': utc_iso(clock.get('SystemTime')),
            'src_ip': ip if event_id != 4740 else 'unknown',
            'username': username,
            'status': 'success' if event_id == 4624 else ('failure' if event_id == 4625 else 'locked'),
            'event_id': event_id,
            'logon_type': fields.get('LogonType', ''),
            'workstation': fields.get('CallerComputerName') or fields.get('WorkstationName') or '',
        }
        yield entry


def write_jsonl(path, records):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for item in records:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


def analyze(input_xml, raw_output, auth_output, alerts_output):
    events = sorted(xml_events(input_xml), key=lambda item: item['timestamp'])
    if not events:
        raise ValueError('No supported Windows Security Events found (4624, 4625 or 4740).')
    # Maintain all events for the investigation tab. Only known-source
    # authentications are passed to correlation: combining "unknown" sources
    # would create fake brute-force / spraying correlations.
    authenticated = [e for e in events if e['status'] in ('success', 'failure') and e['src_ip'] != 'unknown']
    write_jsonl(raw_output, events)
    write_jsonl(auth_output, authenticated)
    alerts = detect(load_events(auth_output))
    # Associate each correlation alert with candidate source records in its
    # 5-minute detection window. This preserves evidence without pretending
    # that a correlation alert has one Windows Event ID.
    from datetime import timedelta
    for alert in alerts:
        moment = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
        start = moment - timedelta(minutes=5)
        matching = []
        for event in authenticated:
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            if not start <= event_time <= moment or event['src_ip'] != alert['src_ip']:
                continue
            if alert['rule'] != 'password_spraying' and event['username'] != alert['username']:
                continue
            if alert['rule'] in ('brute_force', 'password_spraying') and event['status'] != 'failure':
                continue
            matching.append(event)
        alert['source_event_ids'] = sorted({e['event_id'] for e in matching})
        alert['source_record_ids'] = [e['record_id'] for e in matching if e['record_id'] is not None]
    for event in events:
        if event['event_id'] == 4740:
            caller = event['workstation']
            desc = 'Windows reported an account lockout (Event ID 4740).'
            if caller:
                desc += f' Caller computer: {caller}.'
            alerts.append({
                'rule': 'account_lockout',
                'severity': 'medium',
                'timestamp': event['timestamp'],
                'src_ip': 'unknown',  # 4740 contains a caller computer, not a reliable client IP
                'username': event['username'],
                'count': 1,
                'description': desc,
                'mitre_attack': '',  # Lockout alone does not establish an ATT&CK technique
                'event_id': 4740,
                'source_event_ids': [4740],
                'source_record_ids': ([event['record_id']] if event['record_id'] is not None else []),
            })
    alerts.sort(key=lambda item: item['timestamp'])
    path = Path(alerts_output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(alerts, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return len(events), len(authenticated), len(alerts)


def main():
    parser = argparse.ArgumentParser(description='Import Windows Security XML into SOC lab')
    parser.add_argument('--input', default='data/sample_windows_events.xml', help='Event XML path, not .evtx binary')
    parser.add_argument('--raw-output', default='data/windows_events_normalized.jsonl')
    parser.add_argument('--auth-output', default='data/windows_auth.jsonl')
    parser.add_argument('--alerts-output', default='reports/windows_alerts.json')
    args = parser.parse_args()
    try:
        total, auth, alerts = analyze(args.input, args.raw_output, args.auth_output, args.alerts_output)
    except (OSError, ValueError, ET.ParseError) as exc:
        parser.exit(1, f'Error importing Windows XML: {exc}\n')
    print(f'Windows events: {total}; known-IP authentication events: {auth}; alerts: {alerts}')
    print(f'Saved: {args.raw_output} / {args.auth_output} / {args.alerts_output}')
    print('Open Streamlit and choose "Windows Events" in Data Source.')


if __name__ == '__main__':
    main()


import json
from datetime import timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
ALERTS_FILE = ROOT / 'reports' / 'alerts.json'
EVENTS_FILE = ROOT / 'data' / 'generated_auth.jsonl'
VERDICTS_FILE = ROOT / 'reports' / 'analyst_verdicts.json'
VERDICTS = ['Needs Investigation', 'True Positive', 'False Positive']

st.set_page_config(page_title='SOC Threat Detection', page_icon='🛡️', layout='wide')
st.title('🛡️ SOC Threat Detection Dashboard')
st.caption('Security Monitoring | Threat Detection | MITRE ATT&CK | Synthetic demo data')


def read_json(path, default):
    if not path.exists():
        return default
    try:
        with path.open('r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError) as error:
        st.error(f'Could not read {path.name}: {error}')
        st.stop()


def alert_key(alert):
    # Distinguish repeat alerts for the same IP, user and rule at different times.
    return '|'.join(str(alert[col]) for col in ('rule', 'src_ip', 'username', 'timestamp'))


if not ALERTS_FILE.exists():
    st.error('Missing reports/alerts.json. Run detector.py first.')
    st.stop()

alerts = read_json(ALERTS_FILE, [])
if not alerts:
    st.success('No security alerts detected.')
    st.stop()

df = pd.DataFrame(alerts)
required = {'timestamp', 'severity', 'rule', 'src_ip', 'username'}
if not required.issubset(df.columns):
    st.error('Alerts JSON is missing required fields.')
    st.stop()
df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
if df['timestamp'].isna().any():
    st.error('Some alerts have invalid timestamps.')
    st.stop()

if 'filter_version' not in st.session_state:
    st.session_state.filter_version = 0
v = st.session_state.filter_version

st.sidebar.header('🔎 Security Filters')
severity = st.sidebar.multiselect('Severity', sorted(df['severity'].dropna().unique()), key=f'severity_{v}')
attack = st.sidebar.multiselect('Attack Type', sorted(df['rule'].dropna().unique()), key=f'attack_{v}')
ips = st.sidebar.multiselect('Source IP', sorted(df['src_ip'].dropna().unique()), key=f'ip_{v}')
users = st.sidebar.multiselect('Username', sorted(df['username'].dropna().unique()), key=f'user_{v}')
minimum, maximum = df['timestamp'].min().date(), df['timestamp'].max().date()
dates = st.sidebar.date_input('Date Range (UTC)', value=(minimum, maximum), min_value=minimum, max_value=maximum, key=f'dates_{v}')
if st.sidebar.button('Reset Filters'):
    st.session_state.filter_version += 1
    st.rerun()

view = df.copy()
for field, selected in [('severity', severity), ('rule', attack), ('src_ip', ips), ('username', users)]:
    if selected:
        view = view[view[field].isin(selected)]
if len(dates) == 2:
    start, finish = dates
    view = view[(view['timestamp'] >= pd.Timestamp(start, tz='UTC')) &
                (view['timestamp'] < pd.Timestamp(finish + timedelta(days=1), tz='UTC'))]
else:
    st.info('Select both start and end dates to activate date filtering.')

overview, investigation = st.tabs(['📊 Security Overview', '🔍 Incident Investigation'])

with overview:
    st.subheader('Security Overview')
    m1, m2, m3, m4 = st.columns(4)
    m1.metric('Total Alerts', len(df))
    m2.metric('Filtered Alerts', len(view))
    m3.metric('Critical', int((view['severity'] == 'critical').sum()))
    m4.metric('High', int((view['severity'] == 'high').sum()))
    st.divider()
    st.subheader('Detected Security Events')
    if view.empty:
        st.warning('No alerts match the selected filters.')
    else:
        st.dataframe(view.sort_values('timestamp'), use_container_width=True, hide_index=True)
        a, b = st.columns(2)
        with a:
            st.subheader('Alerts by Severity')
            st.bar_chart(view['severity'].value_counts())
        with b:
            st.subheader('Attack Types')
            st.bar_chart(view['rule'].value_counts())
        if 'mitre_attack' in view:
            st.subheader('MITRE ATT&CK Mapping')
            st.dataframe(view[['rule', 'mitre_attack', 'severity']].drop_duplicates(), hide_index=True, use_container_width=True)
        st.download_button('Download Filtered Alerts (JSON)',
                           data=view.to_json(orient='records', date_format='iso', indent=2),
                           file_name='filtered_security_alerts.json', mime='application/json')

with investigation:
    st.subheader('Incident Investigation')
    st.caption('Choose an alert to inspect matching raw authentication events and record a triage verdict.')
    if view.empty:
        st.info('No alerts to investigate. Reset or change filters.')
    else:
        sorted_view = view.sort_values('timestamp').reset_index(drop=True)
        options = sorted_view.index.tolist()
        selected_idx = st.selectbox('Select alert', options, format_func=lambda i: (
            f"{sorted_view.loc[i, 'timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"{sorted_view.loc[i, 'rule']} | {sorted_view.loc[i, 'src_ip']} | "
            f"{sorted_view.loc[i, 'severity'].upper()}"))
        selected = sorted_view.loc[selected_idx]
        c1, c2, c3 = st.columns(3)
        c1.metric('Severity', str(selected['severity']).upper())
        c2.metric('Source IP', str(selected['src_ip']))
        c3.metric('Target User', str(selected['username']))
        st.write('**Rule:**', selected['rule'])
        st.write('**Description:**', selected.get('description', '—'))
        st.write('**MITRE ATT&CK:**', selected.get('mitre_attack', '—'))

        st.subheader('Attack Timeline (Raw Events)')
        if not EVENTS_FILE.exists():
            st.warning('data/generated_auth.jsonl not found. Run generate_logs.py first.')
        else:
            try:
                with EVENTS_FILE.open('r', encoding='utf-8') as file:
                    events = [json.loads(line) for line in file if line.strip()]
                raw = pd.DataFrame(events)
                if not {'timestamp', 'src_ip', 'username', 'status'}.issubset(raw.columns):
                    st.error('Raw log file is missing mandatory fields.')
                elif raw.empty:
                    st.info('No raw events available.')
                else:
                    raw['timestamp'] = pd.to_datetime(raw['timestamp'], utc=True, errors='coerce')
                    moment = selected['timestamp']
                    # Correlation detector default is 5 minutes; 1 minute after shows follow-up activity.
                    timeline = raw[(raw['src_ip'] == selected['src_ip']) &
                                   (raw['timestamp'] >= moment - timedelta(minutes=5)) &
                                   (raw['timestamp'] <= moment + timedelta(minutes=1))].copy()
                    if selected['rule'] != 'password_spraying':
                        timeline = timeline[timeline['username'] == selected['username']]
                    timeline = timeline.sort_values('timestamp')
                    if timeline.empty:
                        st.warning('No matching events in the selected time window. Check whether alerts.json and generated_auth.jsonl came from the same detector run.')
                    else:
                        st.caption('Time window: 5 min before to 1 min after the alert (UTC). Matching IP; account-specific rules also match username.')
                        st.dataframe(timeline[['timestamp', 'src_ip', 'username', 'status']], hide_index=True, use_container_width=True)
                        events_chart = timeline.assign(failure=(timeline['status'] == 'failure').astype(int),
                                                       success=(timeline['status'] == 'success').astype(int))
                        st.bar_chart(events_chart.set_index('timestamp')[['failure', 'success']])
                        st.write(f"**Failures:** {int((timeline['status'] == 'failure').sum())} | **Successes:** {int((timeline['status'] == 'success').sum())}")
            except (OSError, ValueError, json.JSONDecodeError) as error:
                st.error(f'Cannot load raw logs: {error}')

        st.subheader('Analyst Verdict')
        verdicts = read_json(VERDICTS_FILE, {})
        key = alert_key(selected)
        previous = verdicts.get(key, {})
        current = previous.get('verdict', 'Needs Investigation')
        if current not in VERDICTS:
            current = 'Needs Investigation'
        with st.form(key=f'analyst_form_{key}'):
            verdict = st.selectbox('Verdict', VERDICTS, index=VERDICTS.index(current))
            notes = st.text_area('Analyst Notes', value=previous.get('notes', ''),
                                 placeholder='Observed evidence, next investigation steps...')
            saved = st.form_submit_button('Save Verdict')
        if saved:
            verdicts[key] = {'verdict': verdict, 'notes': notes}
            try:
                VERDICTS_FILE.parent.mkdir(parents=True, exist_ok=True)
                with VERDICTS_FILE.open('w', encoding='utf-8') as file:
                    json.dump(verdicts, file, indent=2, ensure_ascii=False)
                st.success(f'Saved {verdict} for the selected alert.')
            except OSError as error:
                st.error(f'Could not save verdict: {error}')
        st.caption('Verdicts are saved locally in reports/analyst_verdicts.json; they do not change the detector output.')

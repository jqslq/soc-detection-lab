# SOC Threat Detection Lab

A Python-based **Blue Team / SOC portfolio project** for detecting suspicious authentication patterns, investigating alerts, and recording analyst triage decisions. The project uses **synthetic logs** and runs locally; it is not a production SIEM.

## Dashboard previews

### 1. Security Overview

Overview of security alerts, severity metrics, and filtering capabilities.

![Security Overview](screenshots/security_overview.png)

### 2. Security Alerts and Visualization

Detection results, alert tables, and attack statistics.

![Security Alerts](screenshots/security_overview_with_alerts.png)

### 3. Incident Investigation

Attack timeline, raw authentication events, and analyst investigation.

![Incident Investigation](screenshots/incident_investigation.png)


## Features

- **Authentication log analysis:** read newline-delimited JSON (JSONL), validate records, and correlate activity by source IP and account.
- **Threat detection:** identify repeated login failures, possible password spraying, and successful sign-in after repeated failures.
- **Severity-based triage:** generate alerts with source IP, affected username, timestamp, priority, and MITRE ATT&CK mapping.
- **Interactive Streamlit dashboard:** filter alerts by severity, detection rule, source IP, username, and UTC date range.
- **Investigation workflow:** view matching raw authentication events in a chronological attack timeline.
- **Analyst verdicts:** record `Needs Investigation`, `True Positive`, or `False Positive` decisions and notes in a local JSON file.
- **Export and testing:** export filtered alerts and run automated detection tests.

## Architecture

```text
Synthetic authentication events (JSONL)
        |
        v
   detector.py  -->  reports/alerts.json
                          |
                          v
                    dashboard.py
                      |      |
                      |      +--> Raw event investigation <-- data/generated_auth.jsonl
                      |
                      +--> Analyst decisions --> reports/analyst_verdicts.json
```

The detector is a **batch-processing** script; the dashboard displays files produced by the detector rather than continuously streaming live events.

## Detection rules

| Detection | Example signal | Demo severity | MITRE ATT&CK |
|---|---|---|---|
| Brute force | At least 5 failed logins targeting one account from one IP within 5 minutes | High | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Password spraying (heuristic) | Failures targeting at least 3 distinct usernames from one IP within 5 minutes | Medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Success after failures | Successful login following at least 5 failures for the same IP and username within 5 minutes | Critical | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |

**Detection caveats:** a spraying alert is only a heuristic because passwords are not available in the logs. A successful login after failures is suspicious but does **not** prove account compromise. Severity reflects a sample triage priority, not confirmed incident impact.

## Technology stack

- Python 3
- Streamlit (web dashboard)
- Pandas (tables, filtering, timestamps)
- JSON / JSONL (logs, alerts, local analyst decisions)
- `unittest` (automated detector checks)

## Quick start (Windows PowerShell)

Open a terminal in the project root. Install dependencies:

```powershell
py -3 -m pip install -r requirements.txt
```

Generate a reproducible synthetic authentication dataset:

```powershell
py -3 generate_logs.py
```

Run the detection engine against the generated dataset:

```powershell
py -3 detector.py --input data/generated_auth.jsonl --output reports/alerts.json
```

Launch the dashboard:

```powershell
py -3 -m streamlit run dashboard.py
```

Open the local URL provided by Streamlit, usually `http://localhost:8501`.

Alternatively, to use the smaller bundled sample dataset:

```powershell
py -3 detector.py --input data/sample_auth.jsonl --output reports/alerts.json
```

**Important:** the investigation timeline currently reads `data/generated_auth.jsonl`. To investigate matching raw events, generate the dataset and run the detector against **that same file**, rather than `sample_auth.jsonl`.

## Input format

The engine accepts one JSON event per line. Required fields:

```json
{"timestamp":"2026-10-15T09:00:00Z","src_ip":"198.51.100.23","username":"admin","status":"failure"}
```

- `timestamp`: ISO 8601 with timezone
- `src_ip`: source IP address
- `username`: attempted account name
- `status`: `failure` or `success`

Example IP addresses belong to documentation-only ranges.

## Investigating an alert

1. Open **Incident Investigation** in the dashboard.
2. Select a suspicious alert (for example, `success_after_failures`).
3. Review the source IP, account, severity, MITRE mapping, and the related raw events timeline.
4. Examine whether failures were followed by a successful sign-in and whether other accounts were targeted.
5. Record an analyst verdict and supporting notes. The dashboard saves decisions in `reports/analyst_verdicts.json`.

Verdicts are a **local training exercise**; they are not an automated remediation or verification of a real security incident.

## Automated tests

```powershell
py -3 -m unittest discover -s tests -v
```

The current suite covers benign authentication activity, validation of missing required fields, and detection of the three sample scenarios.

## Project layout

```text
soc-threat-detection-lab/
├── data/
│   ├── benign_auth.jsonl
│   ├── sample_auth.jsonl
│   └── generated_auth.jsonl       # created by generate_logs.py
├── reports/
│   ├── alerts.json                # detector output
│   └── analyst_verdicts.json      # local; exclude from Git
├── screenshots/
│   ├── security-overview.png
│   └── incident-investigation.png
├── tests/
│   └── test_detector.py
├── dashboard.py
├── detector.py
├── generate_logs.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Limitations and future improvements

- Synthetic data, not a live production log pipeline.
- Static detection thresholds and simplified correlation can produce false positives or miss attacks.
- The timeline reads a predefined generated log path rather than dynamically tracking the detector input.
- Local JSON verdict persistence is suitable for a demo, not for multi-user environments.
- Next steps: parse Windows Security Events (4624/4625), add edge-case tests, support configurable rules, and explore Splunk or another SIEM integration.

## Responsible use

This is a defensive, educational project. No real accounts, credentials, private logs, or sensitive incident notes should be committed to the repository.

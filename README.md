# RDRS - Ransomware Detection and Response System

A **defensive** security tool that watches a folder and the running processes on a
computer, detects ransomware-like behaviour as it happens, scores how dangerous it is,
and responds by raising alerts, creating an incident and saving evidence.

> **Strictly defensive and educational.** RDRS contains no malware. It is tested with a
> small safe simulator (`safe_attack_test.py`) that only creates throwaway files inside
> `data/sandbox`. Automated response runs in **simulation mode**: it logs what it would
> do and never kills a process or changes your files.

## How it detects ransomware

Ransomware encrypts many files very quickly, encrypted data looks random, and files are
often renamed with a new extension. RDRS measures exactly those three behaviours:

| Signal | What is measured | Default trigger |
|---|---|---|
| Rapid encryption | unique files created/modified per minute | 20 or more |
| Mass rename | renames per minute, or extension changes per minute | 15 / 10 or more |
| High entropy | average Shannon entropy (0-8) of new files, at least 5 samples | 7.0 or more |
| CPU spike | busiest process CPU, only counted once file signals fire | 80% or more |
| Unknown program | busiest process runs outside Windows / Program Files, same rule | - |

Each signal that fires adds points. There is no machine learning and no training data,
so every point of a score can be explained.

| Signal | Points |
|---|---|
| Rapid encryption | 40 |
| Mass rename | 30 |
| High entropy | 25 |
| CPU spike | 15 |
| Unknown program | 10 |

The total is capped at 100: **Normal** 0-39, **Warning** 40-69, **Critical** 70-100.
On Critical, RDRS creates an incident record, writes the alert and audit logs, and
**copies** the affected files into a quarantine folder with a manifest. The originals are
never modified or deleted. All weights and thresholds live in `config.yaml`.

## Architecture

    watch  ->  store  ->  analyse  ->  score  ->  respond  ->  show
    (watchdog  (SQLite)   (60 s       (weighted   (alerts,     (REST API,
     + psutil)             window)     rules)      incidents,   dashboard,
                                                   evidence)    reports)

The monitor and the API are separate programs that share one SQLite database file.

    app/
      core/         config loader, rotating logs, entropy, shared models
      detectors/    file monitor, process monitor, detection engine,
                    scoring, incident response, pipeline
      database/     SQLAlchemy tables and access layer
      api/          FastAPI REST API and dashboard routes
      dashboard/    single-page dark dashboard (HTML, Bootstrap, Chart.js)
      reports/      incident reports in JSON and CSV
      main.py       entry point of the monitor
    tests/          unit and integration tests (pytest)
    config.yaml     all settings
    safe_attack_test.py   harmless attack simulator for testing

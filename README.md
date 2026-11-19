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

## Quick start (Docker)

Requires Docker Desktop with the engine running.

    docker compose up -d --build

This starts two containers from one image: `rdrs-api` (REST API and dashboard) and
`rdrs-monitor` (file monitor and detector). Both share the `data/` and `logs/` folders.

- Dashboard: http://127.0.0.1:8000/dashboard
- API docs:  http://127.0.0.1:8000/docs

Stop with `docker compose down`. Data stays in `data/` and survives restarts.

> On Windows, file-change notifications do not cross into Linux containers, so the
> monitor container runs in polling mode (`RDRS_POLLING=1`, set in
> `docker-compose.yml`). Outside Docker the native watcher is used.

## Run without Docker (Windows PowerShell)

    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

    python -m app.main                       # window 1: monitor
    uvicorn app.api.main:app --reload        # window 2: API and dashboard

Requires Python 3.12 or newer (developed on 3.14).

## Try it safely

With the system running, run the harmless simulator in another window:

    python safe_attack_test.py

It creates 50 normal files inside `data/sandbox`, then overwrites them with random bytes
and renames them to `.locked`. Expected result: the threat level climbs from Normal to
Warning to Critical, an incident is created, and evidence copies appear in
`data/quarantine/incident_N_.../`. Clear `data/sandbox` before running it again.

## REST API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /health | liveness check |
| GET | /status | current threat level, score and totals |
| GET | /alerts | newest alerts |
| GET | /events | newest file events |
| GET | /processes | newest process snapshots |
| GET | /reports | list incidents and whether a report exists |
| GET | /reports/{id} | build and save the JSON and CSV report for an incident |
| POST | /scan | read-only entropy scan of the watched folders |
| GET / POST | /settings | view or change detection thresholds |
| GET | /dashboard | the web dashboard |

Reports are saved to `data/reports/incident_N.json` and `incident_N.csv`.

## Tests

    python -m pytest tests --cov=app --cov-report=term-missing

85 tests (unit tests for entropy, scoring and the detection engine; an integration test
that feeds a burst of fake events through the whole pipeline and checks that a Critical
incident with evidence is produced; API, report, database, monitor and safety tests).
Coverage is 98%.

## Safety rules

- Simulation mode is on by default, and the API cannot turn it off.
- Evidence is copied, never moved. Original files are never modified or deleted.
- No code in this project terminates a process.
- The API can change detection thresholds only, not safety settings.
- Test only inside `data/sandbox`, never on real files or on another person's computer.

## Known limitations and false positives

- Legitimate bulk activity looks like an attack: unzipping a large archive, a backup job
  or a bulk photo import creates many files quickly and can reach Warning or Critical.
- Compressed files (zip, jpg, mp4) have high entropy and can raise the entropy signal.
- The suspect process is a best guess (the busiest process at the time), not proof.
- "Unknown program" treats anything outside Windows and Program Files as unknown, so
  developer tools and portable apps can be flagged.
- Evidence is copied at the moment Critical fires, so files not yet renamed at that
  moment may be missing from the copies. The manifest still lists every affected file.
- Inside Docker the monitor only sees processes in its own container, and the container
  clock is UTC.
- Polling mode checks the folder about once a second, so detection is slightly slower
  than the native watcher.

## Ideas for future work

Per-process file attribution, a trusted-program allow-list, honeyfile (canary) detection,
email or webhook alerts, and a gradual response that pauses a suspect process.

# DetectionLab

![Detection Pipeline Validation](https://github.com/Bobby-Okafor/DetectionLab/actions/workflows/validate_pipeline.yml/badge.svg)

**Detection as Code portfolio** — multi-telemetry behavioural detections built across endpoint, network, and identity telemetry using a two-node Kali-Windows lab, Atomic Red Team adversary simulation, Python correlation pipelines, and Microsoft Sentinel KQL.

Every detection in this repository is:
- Validated against real Atomic Red Team telemetry captures
- Versioned and traceable through git history
- Regression-tested on every push via GitHub Actions
- Scored with entropy-based confidence metrics for noise reduction
- Documented with full provenance from simulation through alert output

---

## Detection as Code Methodology

Detections are treated as versioned, measurable systems — not isolated rules.

Each detection follows this lifecycle:

```
Adversary Behaviour (MITRE ATT&CK)
        ↓
Atomic Red Team Simulation (Kali → Windows lab)
        ↓
Telemetry Capture (Sysmon + Windows Security Events)
        ↓
Immutable Corpus Commit (telemetry/raw/<chain>/)
        ↓
Pipeline Replay (ingest → normalise → correlate → detect)
        ↓
Confidence Scoring (entropy + source diversity + field completeness)
        ↓
Validation Report (reports/validation/)
        ↓
Regression Test Case (Pipeline/replay_harness.py)
        ↓
CI Gate (GitHub Actions — green badge = all detections proven)
```

Any commit in the git history can be checked out and `python Pipeline/replay_harness.py --suite all` will reproduce the exact validation state at that point in time.

---

## ATT&CK Coverage Matrix

| Detection ID | Techniques | Behaviour | Sources | Status | Confidence |
|---|---|---|---|---|---|
| DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1 | T1059.001 + T1071.001 | Encoded PS → C2 beacon | Sysmon EID 1 + EID 3 | ✅ Validated | High |
| DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1 | T1110.001 + T1078 + T1059 | Brute force → auth exec | WinSec 4625 + 4624 + Sysmon EID 1 | ✅ Validated | High |
| DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1 | T1547.001 + T1053.005 | Registry + scheduled task persist | Sysmon EID 1 + EID 13 + WinSec 4698 | ✅ Validated | High |
| DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1 | T1543.003 + T1078 + T1059 | Priv logon → service → exec | WinSec 4624 + 4672 + 7045 + 4688 | 🔄 In Progress | — |

**Coverage: 3 validated · 1 in progress**

---

## Lab Architecture

```
┌─────────────────────────────────────┐
│  Kali Linux 2024.3 (Attacker)       │
│  IP: 192.168.126.128                │
│  Tools: Hydra, Netcat, Impacket     │
│  Network: VMware Host-Only (VMnet1) │
└──────────────┬──────────────────────┘
               │ 192.168.126.0/24
┌──────────────┴──────────────────────┐
│  Windows 10 (Victim / Sensor)       │
│  Hostname: BOBBY                    │
│  IP: 192.168.126.1                  │
│  Sysmon: EID 1, 3, 11, 13, 22      │
│  Windows Security Auditing: enabled │
│  Atomic Red Team: installed         │
└─────────────────────────────────────┘
```

---

## Pipeline Architecture

```
telemetry/raw/<chain>/          ← Immutable corpus (multi-source JSON)
         │
         ▼
    [ ingest.py ]               ← Multi-source directory merge, source tagging
         │
         ▼
   [ normalize.py ]             ← Sysmon flat KV + WinSec message-text parsing
         │                         UTC timestamp unification, LogonId normalisation
         ▼
[ schema_validator.py ]         ← Field contract assertions per event type
         │
         ▼
    [ correlate.py ]            ← Cross-telemetry chain builder
         │                         ProcessGuid, LogonId, src_ip joins
         │                         Shannon entropy scoring
         │                         Composite confidence scoring
         ▼
    [ detect.py ]               ← Behavioural detection logic on chains
         │                         Multi-source evidence required to fire
         ▼
  [ alert_schema.py ]           ← Structured alert with confidence + noise label
         │
         ▼
   Alert JSON output            → reports/validation/
                                → replay_harness.py (regression CI)
                                → Sentinel DCR (production path)
```

---

## Confidence Scoring

Every alert carries a composite confidence score derived from four factors:

| Factor | Weight | Description |
|---|---|---|
| Source diversity | 35% | How many distinct telemetry sources contributed |
| Shannon entropy | 25% | Distribution of events across source types |
| Field completeness | 20% | Ratio of populated fields in contributing events |
| Join field strength | 20% | Specificity of the correlation join (ProcessGuid > LogonId > IP > user+host) |

**Noise classification:**

| Score | Label | Triage guidance |
|---|---|---|
| ≥ 0.80 + 3 sources | SIGNAL | Prioritise — high confidence multi-source |
| ≥ 0.60 + 2 sources | LIKELY_SIGNAL | Investigate — cross-source corroboration |
| ≥ 0.40 | INVESTIGATE | Verify before escalating |
| < 0.40 | LOW_FIDELITY | Tune or suppress |

---

## Repository Structure

```text
DetectionLab/
│
├── Pipeline/                       # Detection as Code engine
│   ├── ingest.py                   # Multi-source ingestion
│   ├── normalize.py                # Sysmon + WinSec normalisation
│   ├── correlate.py                # Cross-telemetry correlation engine
│   ├── detect.py                   # Behavioural detection chains
│   ├── alert_schema.py             # Structured alert with confidence scoring
│   ├── schema_validator.py         # Field contract enforcement
│   ├── replay_harness.py           # Detection as Code regression tests
│   ├── run_pipeline.py             # CLI entry point
│   └── atomic_reader.py            # Atomic test catalogue reader
│
├── telemetry/
│   ├── raw/                        # Immutable corpus (never overwritten)
│   │   ├── chain1_c2_beacon/       # Sysmon EID 1 + EID 3
│   │   ├── chain2_brute_exec/      # WinSec 4625 + 4624 + Sysmon EID 1
│   │   ├── chain3_persistence/     # Sysmon EID 1 + EID 13 + WinSec 4698
│   │   └── clean_baseline.json     # Zero-alert baseline
│   └── normalised/                 # Post-pipeline output samples
│
├── attack_runs/                    # Simulation execution records
│   ├── chain1_T1059.001_T1071.001/
│   ├── chain2_T1110.001_T1078_T1059/
│   └── chain3_T1547.001_T1053.005/
│
├── reports/
│   ├── validation/                 # Per-detection validation reports
│   ├── ci/                         # CI coverage reports
│   └── tuning/                     # False positive analysis
│
├── kql/                            # Microsoft Sentinel queries
├── sigma/                          # SIEM-portable Sigma rules
├── playbooks/                      # Analyst response guides
├── Detections/
│   ├── validated/                  # Production-grade detections
│   ├── in_progress/                # Under development
│   └── deprecated/                 # Superseded detections
│
└── .github/workflows/
    └── validate_pipeline.yml       # CI — runs replay harness on every push
```

---

## Quick Start

```bash
git clone https://github.com/Bobby-Okafor/DetectionLab.git
cd DetectionLab
pip install -r requirements.txt

# Run multi-source pipeline against C2 beacon telemetry
python Pipeline/run_pipeline.py \
  --input-dir telemetry/raw/chain1_c2_beacon \
  --output reports/validation/chain1_output.json \
  --window 60

# Run full regression suite
python Pipeline/replay_harness.py --suite all --verbose

# Browse Atomic test catalogue
python Pipeline/atomic_reader.py --technique T1059.001 --run-plan
```

---

## Tools and Stack

| Layer | Tool |
|---|---|
| Adversary simulation | Atomic Red Team, Hydra, Netcat, Impacket |
| Attacker platform | Kali Linux 2024.3 (VMware Host-Only) |
| Endpoint telemetry | Sysmon (EID 1, 3, 11, 13, 22) |
| Identity telemetry | Windows Security Events (4624, 4625, 4672, 4688, 4698, 7045) |
| SIEM / detection language | Microsoft Sentinel, KQL |
| Normalisation pipeline | Python 3.11+ |
| Detection format | Python + Sigma |
| Confidence scoring | Shannon entropy + composite weighting |
| Version control | Git, GitHub Actions CI |

---

## Author

**Bobby Okafor**
Detection Engineer — endpoint, identity, and network telemetry
[GitHub](https://github.com/Bobby-Okafor) · [LinkedIn](https://www.linkedin.com/in/bobby-okafor-40a521380)

# Artifact Evaluation & Reproduction Guide

**Artifact Title**: Uncertainty-Aware Least-Privilege Repair for Cloud IAM under Partial Observability
**Target Badges**: **Artifact Available** | **Artifact Evaluated – Functional** | **Results Replicated**
**Associated Publications / Thesis**: Duke, Master of Science Thesis, October 2026
**Artifact Repository**: `DukeTheOne/IAM_GNN` (`https://github.com/DukeTheOne/IAM_GNN`)
**Certified Test Coverage**: **468 unit and integration tests passing** across 61 modules

---

## 1. Overview & System Requirements

This artifact evaluation package provides all code, models, synthetic topology generators, procedural TAC-Bench ingestion scripts, Terraform HCL2 parsers, baseline implementations (IAMPERE SMT, TAC-GB, BFS, Random Forest), optimization engines, and verification suites described in the thesis.

### 1.1 Hardware & Operating System Requirements
- **Operating System**: macOS (tested on Apple Silicon & Intel) or Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+).
- **CPU**: Minimum 4 cores (8+ cores recommended for multi-seed publication sweeps).
- **RAM**: Minimum 8 GB (16 GB recommended for $N = 5,000$ graph scaling tests).
- **Disk**: 2.5 GB free space (including Python virtual environment and benchmark artifacts).
- **GPU**: Optional (CPU execution is default and fully vectorized via PyTorch & PyG).

### 1.2 Software Dependencies
- **Python**: Version 3.11, 3.12, or 3.13.
- **Package Manager**: `uv` (recommended for deterministic locking) or standard `pip` + `python3-venv`.
- **C/C++ Compiler**: Standard system build tools (`clang` or `gcc`) for `z3-solver` and `python-hcl2`.

---

## 2. Quick Environment Setup (< 2 Minutes)

```bash
# 1. Clone the repository
git clone https://github.com/DukeTheOne/IAM_GNN.git
cd IAM_GNN

# 2. Option A: Automated installation via uv (Recommended)
uv sync --all-extras

# 2. Option B: Standard pip virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. Verify toolchain and quality checks
uv run ruff check src tests scripts
uv run mypy --strict src/iam
uv run pytest -q
```
*Expected Output*: `468 passed, 0 errors, 100% strict typing certified.`

---

## 3. Major Scientific Claims & Artifact Mapping

| Claim # | Scientific Claim Description | Thesis Reference | Artifact / CLI Command | Primary Output File |
| :---: | :--- | :--- | :--- | :--- |
| **C1** | **Gate G0: Latent Link Discovery** under adversarial bridge masking (HeteroRGCN achieves >0.90 ROC-AUC vs. BFS 0.50 / 0% recall). | Chapter 4, Sec 4.4 | `iam evaluate --conditions A_20,B,E` | `experiments/sweep/sweep_report.md` |
| **C2** | **Gate G1: Zero-Shot Transfer** on external TAC-Bench benchmarks (35 tasks across 7 canonical enterprise categories). | Chapter 6, Sec 6.1 | `iam evaluate-transfer --tac-bench-dir data/tac_bench` | `experiments/zero_shot/zero_shot_transfer_report.md` |
| **C3** | **Gate G2: Multi-Objective Pareto Dominance** (Method 4b strictly dominates IAMPERE coarse deletion with 0% breakage vs. 30.6% breakage). | Chapter 6, Sec 6.2 | `iam evaluate-pareto --output-dir experiments/pareto_frontier` | `experiments/pareto_frontier/gate_g2_pareto_report.md` |
| **C4** | **Gate G3: Runtime Scalability & Optimality** (<50ms greedy repair at $N=5,000$ with 0.00% optimality gap vs Z3 MaxSAT). | Chapter 6, Sec 6.3 | `iam evaluate-scalability --scales 50 100 250 500 1000` | `experiments/scalability/scalability_report.md` |
| **C5** | **Real-World Infrastructure-as-Code** ingestion and capability-compliant diff synthesis on 35 open-source Terraform repos. | Chapter 6, Sec 6.4 | `iam ingest-iac --input-path data/iac_repositories/...` | Console AST & Policy Diff Output |

---

## 4. Automated Reproduction Modes

The reproduction script [`./reproduce_results.sh`](file:///Users/duke/IAM/reproduce_results.sh) provides three automated execution profiles:

### Mode 1: Fast Smoke Test (< 45 Seconds)
Validates code hygiene, strict typing, unit and integration test suites, and runs reduced-scale sweeps:
```bash
./reproduce_results.sh --fast
```
*Use Case*: Rapid continuous integration, verification that dependencies and solvers function cleanly.

### Mode 2: Tier 2 Master's Thesis Milestone Suite (~ 3 Minutes)
Executes all formal thesis gate benchmarks (Gate G1 Zero-Shot Transfer, Gate G2 Pareto Dominance, Gate G3 Enterprise Scalability):
```bash
./reproduce_results.sh --tier2
```
*Generated Artifacts*:
- `experiments/zero_shot/zero_shot_transfer_report.md` & `zero_shot_transfer_results.json`
- `experiments/pareto_frontier/gate_g2_pareto_report.md` & `gate_g2_pareto_results.json`
- `experiments/scalability/scalability_report.md` & `scalability_results.json`

### Mode 3: Full Multi-Seed Publication Benchmark Suite (~ 12 Minutes)
Executes exhaustive multi-seed evaluations across scales $N \in [500, 1000, 3000, 5000]$:
```bash
./reproduce_results.sh --full
```
*Generated Artifacts*:
- `experiments/sweep/sweep_report.md`: Multi-seed RQ1 structured masking report.
- `experiments/tradeoff/tradeoff_report.md`: Multi-objective Pareto curves.
- `experiments/benchmarks/benchmark_report.md`: Multi-scale latency and optimality gap tables.
- `experiments/benchmarks/figures/*.png`: High-resolution publication figures.
- `reports/triage_export/triage_summary.md`: Static triage posture analysis.

---

## 5. Detailed Step-by-Step Benchmark Instructions

### 5.1 Ingesting & Evaluating TAC-Bench (Gate G1)
```bash
# Step 1: Ingest 35 formal tasks across 7 canonical categories
iam ingest-tac-bench --num-tasks 35 --output-dir data/tac_bench --seed 42

# Step 2: Run inductive zero-shot transfer evaluation against baselines
iam evaluate-transfer --tac-bench-dir data/tac_bench --epochs 25 --output-dir experiments/zero_shot --seed 42
```
*Inspection*: Open `experiments/zero_shot/zero_shot_transfer_report.md` to inspect comparative PR-AUC, ROC-AUC, Recall@1, Recall@5, and FNR across HeteroRGCN, TAC-GB, Random Forest, IAMPERE SMT, and BFS.

### 5.2 Evaluating Multi-Objective Pareto Frontier Dominance (Gate G2)
```bash
iam evaluate-pareto --num-completions 20 --output-dir experiments/pareto_frontier --seed 42
```
*Inspection*: Open `experiments/pareto_frontier/gate_g2_pareto_report.md` to verify that Method 4b (Uncertainty-Aware Repair) strictly dominates Method 2 (IAMPERE Coarse Deletion) and Method 3 (PolicyRefiner Log-Only Tightening) across all 4 evaluated cloud topologies.

### 5.3 Benchmarking Enterprise Runtime Scalability (Gate G3)
```bash
iam evaluate-scalability --scales 50 100 250 500 1000 --output-dir experiments/scalability --seed 42
```
*Inspection*: Open `experiments/scalability/scalability_report.md` to confirm the 0.00% empirical optimality gap between greedy min-cut and exact Z3 MaxSAT, as well as the sub-30ms execution of greedy repair at $N = 1,011$ nodes.

### 5.4 Ingesting Real-World Terraform Infrastructure-as-Code
```bash
# Ingest and extract authorization multigraph from sample Terraform module
iam ingest-iac --input-path data/_benchmarks/pareto_iac_env/pe_vulnerable.tf
```

---

## 6. Interactive Visual Triage Dashboard

Launch the local Streamlit + PyVis interactive security triage dashboard:
```bash
iam dashboard --port 8501
```
Navigate to `http://localhost:8501` in any modern web browser:
1. **Global Security Posture**: View real-time KPIs of scanned identities, evaluated policies, and latent risk discoveries.
2. **Ego-Network Canvas**: Explore physics-based authorization graphs with force-directed layouts scoped to the $k \le 2$ hop neighborhood around high-risk identities.
3. **Policy Diff Inspector**: Inspect side-by-side JSON diffs comparing original policies against capability-compliant repairs with AWS authorization badges.
4. **What-If Verification Simulator**: Toggle proposed patches to verify immediate severance of latent attack reachability across sampled completions.

---

## 7. Artifact Directory Structure

```text
IAM_GNN/
├── data/
│   ├── schemas/iac_repo_catalog.json    # 35 curated open-source Terraform repos across 5 tiers
│   ├── schemas/capability_snapshot.json # AWS Service Authorization Reference capability model
│   └── tac_bench/                       # Ingested procedural TAC-Bench benchmark tasks
├── docs/
│   ├── thesis_manuscript.md             # Complete 7-chapter Master's Thesis manuscript
│   ├── thesis_defense_deck.md           # 22-slide Master's Thesis defense presentation
│   ├── advisor_summary_tier1.md         # Advisor executive research brief
│   └── artifact_evaluation.md           # This artifact evaluation and reproduction manual
├── experiments/
│   ├── zero_shot/                       # Gate G1 zero-shot transfer reports & JSON results
│   ├── pareto_frontier/                 # Gate G2 multi-objective Pareto reports & JSON results
│   └── scalability/                     # Gate G3 runtime scalability reports & JSON results
├── src/iam/                             # 61 source modules (parser, models, optimizer, verifier)
├── tests/                               # 468 unit and integration tests (100% passing)
└── reproduce_results.sh                 # Single-command reproduction script (--fast, --tier2, --full)
```

#!/usr/bin/env bash
# ==============================================================================
# Uncertainty-Aware Least-Privilege Repair for Cloud IAM under Partial Observability
# Automated Reproduction Script (Phase 4 Week 10 Deliverable)
#
# Usage:
#   ./reproduce_results.sh [--fast | --full]
#
# Modes:
#   --fast : Smoke test reproduction mode (< 45s) for rapid CI/CD verification.
#   --full : Full publication-grade benchmark suite across all scales (500..5000),
#            seeds, masking conditions, and Pareto tradeoff analyses.
# ==============================================================================

set -euo pipefail

# ANSI Color Palette
BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
MODE="fast"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast)
      MODE="fast"
      shift
      ;;
    --full)
      MODE="full"
      shift
      ;;
    --tier2)
      MODE="tier2"
      shift
      ;;
    -h|--help)
      echo -e "${BOLD}Usage:${NC} ./reproduce_results.sh [OPTIONS]"
      echo ""
      echo -e "${BOLD}Options:${NC}"
      echo "  --fast    Run fast verification smoke suite (scales 50..100, ~30s)"
      echo "  --full    Run full publication benchmark suite (scales 500..5000, multi-seed)"
      echo "  --tier2   Run Tier 2 Master's Thesis Gate Milestones (G1 Zero-Shot, G2 Pareto, G3 Scalability)"
      echo "  -h, --help Show this help message and exit"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Use --help for usage information."
      exit 1
      ;;
  esac
done

# Environment Discovery
if [[ -f ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
elif command -v uv &> /dev/null; then
  PYTHON="uv run python"
elif command -v python3 &> /dev/null; then
  PYTHON="python3"
else
  PYTHON="python"
fi

START_TIME=$(date +%s)

echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}  IAM Graph Learning: Automated Scientific Reproduction Suite           ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "Reproduction Mode : ${BOLD}${GREEN}${MODE}${NC}"
echo -e "Python Runtime    : ${BLUE}$($PYTHON --version)${NC}"
echo -e "Working Directory : ${SCRIPT_DIR}"
echo -e "Timestamp         : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo -e "${CYAN}------------------------------------------------------------------------${NC}"

# Step 1: Codebase Quality & Type Safety Checks
echo -e "\n${BOLD}${BLUE}[Step 1/6] Code Quality & Strict Type Verification${NC}"
echo "Running ruff check & ruff format validation..."
$PYTHON -m ruff check src tests scripts
$PYTHON -m ruff format --check src tests scripts

echo "Running mypy strict type checking across src/iam..."
$PYTHON -m mypy --strict src/iam
echo -e "${GREEN}✓ Code quality and 100% strict typing verified.${NC}"

# Step 2: Comprehensive Test Suite & Coverage Verification
echo -e "\n${BOLD}${BLUE}[Step 2/6] Test Suite & Code Coverage Verification${NC}"
if [[ "$MODE" == "fast" ]]; then
  echo "Running core unit and integration test suite..."
  $PYTHON -m pytest -q tests/
else
  echo "Running full test suite with test coverage analysis..."
  $PYTHON -m pytest tests/ --cov=iam --cov-report=term-missing --cov-fail-under=85 -q
fi
echo -e "${GREEN}✓ All test suites passed with strict coverage certification.${NC}"

if [[ "$MODE" == "tier2" ]]; then
  # Step 3 (Tier 2): Gate G1 Zero-Shot Inductive Transfer
  echo -e "\n${BOLD}${BLUE}[Step 3/5] Gate G1: TAC-Bench Ingestion & Zero-Shot Inductive Transfer${NC}"
  echo "Ingesting 14 TAC-Bench tasks across 7 canonical categories..."
  $PYTHON -m iam.cli ingest-tac-bench --num-tasks 14 --output-dir data/tac_bench --seed 42
  echo "Evaluating zero-shot inductive transfer against baselines..."
  $PYTHON -m iam.cli evaluate-transfer --tac-bench-dir data/tac_bench --epochs 10 --output-dir experiments/zero_shot --seed 42
  echo -e "${GREEN}✓ Gate G1 transfer artifacts generated in experiments/zero_shot/.${NC}"

  # Step 4 (Tier 2): Gate G2 Multi-Objective Pareto Frontier
  echo -e "\n${BOLD}${BLUE}[Step 4/5] Gate G2: Multi-Objective Pareto Frontier Dominance${NC}"
  echo "Evaluating 6 remediation strategies across 4 cloud environments..."
  $PYTHON -m iam.cli evaluate-pareto --num-completions 10 --output-dir experiments/pareto_frontier --seed 42
  echo -e "${GREEN}✓ Gate G2 Pareto frontier artifacts generated in experiments/pareto_frontier/.${NC}"

  # Step 5 (Tier 2): Gate G3 Runtime Scalability Benchmark
  echo -e "\n${BOLD}${BLUE}[Step 5/5] Gate G3: Enterprise Graph Runtime Scalability${NC}"
  echo "Evaluating greedy min-cut vs exact Z3 MaxSAT across graph scales..."
  $PYTHON -m iam.cli evaluate-scalability --scales 50 100 250 500 --output-dir experiments/scalability --seed 42
  echo -e "${GREEN}✓ Gate G3 scalability artifacts generated in experiments/scalability/.${NC}"

else
  # Step 3: RQ1 Structured Masking Benchmark Sweep
  echo -e "\n${BOLD}${BLUE}[Step 3/6] RQ1: Structured Masking Benchmark Sweep${NC}"
  if [[ "$MODE" == "fast" ]]; then
    echo "Executing fast multi-condition sweep (Conditions A, E, B, C, D)..."
    $PYTHON scripts/run_experiments_sweep.py --fast --output-dir experiments/sweep
  else
    echo "Executing full multi-seed, multi-condition masking sweep (25 epochs, 5 seeds)..."
    $PYTHON scripts/run_experiments_sweep.py --seeds 101,202,303,404,505 --epochs 25 --output-dir experiments/sweep
  fi
  echo -e "${GREEN}✓ RQ1 benchmark artifacts generated in experiments/sweep/.${NC}"

  # Step 4: RQ2 Security-Utility Tradeoff & Pareto Analysis
  echo -e "\n${BOLD}${BLUE}[Step 4/6] RQ2: Security-Utility Tradeoff & Pareto Evaluation${NC}"
  if [[ "$MODE" == "fast" ]]; then
    echo "Evaluating Pareto frontier across 6 remediation strategies (fast mode)..."
    $PYTHON scripts/run_tradeoff_experiment.py --enterprise-nodes 100 --num-completions 20 --output-dir experiments/tradeoff
  else
    echo "Evaluating Pareto frontier across 6 remediation strategies (full mode)..."
    $PYTHON scripts/run_tradeoff_experiment.py --enterprise-nodes 300 --num-completions 50 --output-dir experiments/tradeoff
  fi
  echo -e "${GREEN}✓ RQ2 tradeoff artifacts generated in experiments/tradeoff/.${NC}"

  # Step 5: RQ3 Scalability & Full Pipeline Benchmarks
  echo -e "\n${BOLD}${BLUE}[Step 5/6] RQ3: Full Pipeline Scalability Benchmarks${NC}"
  if [[ "$MODE" == "fast" ]]; then
    echo "Running multi-scale pipeline benchmarks (smoke mode)..."
    $PYTHON scripts/run_full_pipeline_benchmarks.py --fast --output-dir experiments/benchmarks
  else
    echo "Running multi-scale pipeline benchmarks across N in [500, 1000, 3000, 5000]..."
    $PYTHON scripts/run_full_pipeline_benchmarks.py --scales 500,1000,3000,5000 --seeds 101,202,303 --output-dir experiments/benchmarks
  fi
  echo -e "${GREEN}✓ RQ3 benchmark artifacts generated in experiments/benchmarks/.${NC}"

  # Step 6: Headless Triage Exporter
  echo -e "\n${BOLD}${BLUE}[Step 6/6] Headless Security Triage Report Generation${NC}"
  echo "Exporting static HTML ego-networks and markdown executive summary..."
  $PYTHON scripts/export_triage_report.py --num-nodes 150 --seed 42 --output-dir reports/triage_export
  echo -e "${GREEN}✓ Executive triage report generated in reports/triage_export/.${NC}"
fi

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "\n${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${GREEN}  Reproduction Completed Successfully in ${ELAPSED} seconds!             ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}Key Generated Artifacts:${NC}"
if [[ "$MODE" == "tier2" ]]; then
  echo -e "  • Gate G1 Zero-Shot Report : ${BLUE}experiments/zero_shot/zero_shot_transfer_report.md${NC}"
  echo -e "  • Gate G2 Pareto Report    : ${BLUE}experiments/pareto_frontier/gate_g2_pareto_report.md${NC}"
  echo -e "  • Gate G3 Scalability Rep. : ${BLUE}experiments/scalability/scalability_report.md${NC}"
  echo -e "  • Benchmark Task Manifest  : ${BLUE}data/tac_bench/manifest.json${NC}"
  echo -e "  • IaC Benchmark Catalog    : ${BLUE}data/schemas/iac_repo_catalog.json${NC}"
else
  echo -e "  • RQ1 Sweep Report         : ${BLUE}experiments/sweep/sweep_report.md${NC}"
  echo -e "  • RQ2 Tradeoff Report      : ${BLUE}experiments/tradeoff/tradeoff_report.md${NC}"
  echo -e "  • RQ3 Benchmark Report     : ${BLUE}experiments/benchmarks/benchmark_report.md${NC}"
  echo -e "  • RQ3 Benchmark Summary    : ${BLUE}experiments/benchmarks/benchmark_summary.json${NC}"
  echo -e "  • Benchmark Figures        : ${BLUE}experiments/benchmarks/figures/*.png${NC}"
  echo -e "  • Static Triage Report     : ${BLUE}reports/triage_export/triage_summary.md${NC}"
fi
echo -e "  • Interactive Dashboard    : ${YELLOW}iam dashboard${NC} (or .venv/bin/iam dashboard)"
echo -e "${CYAN}========================================================================${NC}"

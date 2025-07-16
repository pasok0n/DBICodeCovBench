#!/bin/bash

# ==============================================================================
# This script automates the process of running the 'bb_docker.sh' command
# for various combinations of Docker images, analysis tools (Frida,
# Dynamorio, Pin), and execution modes (attach, spawn).
#
# It takes three command-line arguments:
# 1. The results directory to store all outputs (created if it does not exist).
# 2. The number of times to run each combination.
# 3. The duration (in seconds) for each run.
#
# Usage: ./run_all.sh <results_dir> <number_of_runs> <time_in_seconds>
# Example: ./run_all.sh my_results 4 60
# ==============================================================================

# Exit immediately if any command fails.
set -e

# --- Configuration -----------------------------------------------------------

IMAGES=(
  "dcmtk"
  "bind9"
  "dnsmasq"
  "webfsd"
  "bftpd"
  "lightftp"
  "proftpd"
  "pureftpd"
  "m-bus"
  "live555"
  "kamailio"
  "openssh"
  "tinydtls"
  "simple-http-server"
  "node"
)

TOOLS=("frida" "dynamorio" "pin")
MODES=("attach" "spawn")

# --- Colour Definitions ------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'   # No Colour

# --- Argument Validation -----------------------------------------------------

if [ "$#" -ne 3 ]; then
  echo -e "${RED}Error: Invalid number of arguments.${NC}"
  echo "Usage: $0 <results_dir> <number_of_runs> <time_in_seconds>"
  echo "Example: $0 my_results 4 60"
  exit 1
fi

RESULTS_DIR=$1
NUM_RUNS=$2
RUN_TIME=$3

# Create the results directory if it does not already exist.
mkdir -p "$RESULTS_DIR"

# --- Prerequisite Check ------------------------------------------------------

if ! command -v bb_docker.sh &>/dev/null; then
  echo -e "${RED}Error: 'bb_docker.sh' command not found in your \$PATH.${NC}"
  echo "Ensure the script is executable (chmod +x bb_docker.sh) and in \$PATH."
  exit 1
fi

# --- Main Execution Logic ----------------------------------------------------

echo -e "${YELLOW}Starting batch run process...${NC}"
echo "Results directory: ${CYAN}${RESULTS_DIR}${NC}"
echo "Number of runs per combination: ${CYAN}${NUM_RUNS}${NC}"
echo "Time per run: ${CYAN}${RUN_TIME} seconds${NC}"

for image in "${IMAGES[@]}"; do
  for tool in "${TOOLS[@]}"; do
    for mode in "${MODES[@]}"; do
      output_name="${image}-${tool}-${mode}"

      echo "--------------------------------------------------"
      echo -e "Running combination:"
      echo -e "  Image:   ${GREEN}${image}${NC}"
      echo -e "  Tool:    ${GREEN}${tool}${NC}"
      echo -e "  Mode:    ${GREEN}${mode}${NC}"
      echo -e "  Output:  ${GREEN}${output_name}${NC}"
      echo -e "  Folder:  ${GREEN}${RESULTS_DIR}${NC}"
      echo "--------------------------------------------------"

      bb_docker.sh \
        "$image" \
        "$NUM_RUNS" \
        "$RESULTS_DIR" \
        "$tool" \
        "$mode" \
        "$output_name" \
        "$RUN_TIME"

      echo -e "${GREEN}Combination finished successfully.${NC}"
    done
  done
done

echo "=================================================="
echo -e "${GREEN}All combinations have been executed!${NC}"
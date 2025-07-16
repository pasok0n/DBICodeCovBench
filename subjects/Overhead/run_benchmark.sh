#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <docker_image_name> <output_directory>"
    exit 1
fi

DOCKER_IMAGE_NAME=$1
OUTPUT_DIR=$2
CONTAINER_NAME="benchmark_container_$$" # Unique name for each run

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Starting Docker container: $DOCKER_IMAGE_NAME"
echo "Results will be saved to: $OUTPUT_DIR"

# Run the Docker container in detached mode and get its ID
CONTAINER_ID=$(docker run --privileged --cap-add=SYS_PTRACE --security-opt seccomp:unconfined --security-opt apparmor:unconfined -d --name "$CONTAINER_NAME" "$DOCKER_IMAGE_NAME" sleep infinity)

if [ -z "$CONTAINER_ID" ]; then
    echo "Error: Failed to start Docker container."
    exit 1
fi

echo "Container ID: $CONTAINER_ID"
echo "Entering container and running ./run.sh..."

# Execute the script inside the container
docker exec -w /home/ubuntu/experiments "$CONTAINER_ID" ./run.sh

if [ $? -ne 0 ]; then
    echo "Error: ./run.sh failed inside the container."
    docker stop "$CONTAINER_ID"
    docker rm "$CONTAINER_ID"
    exit 1
fi

echo "Copying results from container to host..."

# Define the list of files to copy
FILES_TO_COPY=(
    "performance_report.txt"
    "baseline_timing_data.csv"
    "baseline_perf_data.csv"
    "dynamorio_timing_data.csv"
    "dynamorio_perf_data.csv"
    "pin_timing_data.csv"
    "pin_perf_data.csv"
    "frida_timing_data.csv"
    "frida_perf_data.csv"
)

# Copy each file from the container to the host's output directory
for file in "${FILES_TO_COPY[@]}"; do
    docker cp "$CONTAINER_ID:/home/ubuntu/experiments/$file" "$OUTPUT_DIR/$file"
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to copy $file from container."
    else
        echo "Copied: $file"
    fi
done

echo "Stopping Docker container..."
docker stop "$CONTAINER_ID"

echo "Benchmark execution and data retrieval complete."
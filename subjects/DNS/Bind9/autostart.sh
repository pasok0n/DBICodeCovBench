#!/bin/bash

# Check if toolname is provided
if [ -z "$1" ]; then
  echo "Usage: ./autorun.sh <toolname>"
  exit 1
fi

TOOLNAME=$1

# Build the Docker image
docker build . -t "$TOOLNAME"

# Run bb_docker.sh with spawn and attach commands
./../../../scripts/bb_docker.sh "$TOOLNAME" 4 results-bind9 dynamorio spawn spawn 5
./../../../scripts/bb_docker.sh "$TOOLNAME" 4 results-bind9 dynamorio attach attach 5

# Navigate to results-bind9 directory
cd results-bind9 || { echo "Directory results-bind9 not found"; exit 1; }

# Create hexdump output file
HEXDUMP_FILE="hexdump_output.txt"
echo "Hexdump analysis for $TOOLNAME - $(date)" > "$HEXDUMP_FILE"
echo "================================================" >> "$HEXDUMP_FILE"

# Define arrays for directories and files
MODES=("attach" "spawn")
NUMBERS=(1 2 3 4)
BITMAPS=(0 1)

# Perform hexdump operations using loops
for mode in "${MODES[@]}"; do
    for num in "${NUMBERS[@]}"; do
        for bitmap in "${BITMAPS[@]}"; do
            dir="${mode}_${num}"
            file="dr_afl_bitmap_${bitmap}.bin"
            filepath="$dir/$file"
            
            echo "Hexdump for $filepath:"
            echo "Hexdump for $filepath:" >> "$HEXDUMP_FILE"
            
            if [ -f "$filepath" ]; then
                hexdump -C "$filepath" | head -10 >> "$HEXDUMP_FILE"
            else
                echo "File not found: $filepath" >> "$HEXDUMP_FILE"
            fi
            
            echo "" >> "$HEXDUMP_FILE"
        done
    done
done

echo "Hexdump analysis completed. Output saved to $HEXDUMP_FILE"
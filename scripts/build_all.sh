#!/bin/bash

# ==============================================================================
# This script iterates through a predefined list of project directories,
# changes into each one, and builds the Docker image using the Dockerfile
# found there.
#
# It automatically generates a Docker image tag from the final directory's
# name, converted to lowercase. For example, a directory "DICOM/Dcmtk"
# will result in an image tagged as "dcmtk".
# ==============================================================================

# Exit immediately if any command fails.
set -e

# --- Configuration ---

# Define the base directory where your subject folders are located.
BASE_DIR="subjects"

# List of project sub-directories to process.
PROJECTS=(
  "DICOM/Dcmtk"
  "DNS/Bind9"
  "DNS/Dnsmasq"
  "FTP/BFTPD"
  "FTP/LightFTP"
  "FTP/ProFTPD"
  "FTP/PureFTPD"
  "HTTP/webfsd"
  "HTTP/Simple-HTTP-Server"
  "HTTP/Node"
  "MODBUS/M-bus"
  "RTSP/Live555"
  "SIP/Kamailio"
  "SSH/OpenSSH"
  "DTLS/TinyDTLS"
  # Add more project paths here
)

# --- Color Definitions for Readable Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Main Script Logic ---

echo -e "${YELLOW}Starting Docker build process for all projects...${NC}"

# Store the directory where the script was started.
START_DIR=$(pwd)

# Loop through each project defined in the PROJECTS array.
for project in "${PROJECTS[@]}"; do
  full_path="$BASE_DIR/$project"

  echo "--------------------------------------------------"
  echo -e "Processing project in: ${YELLOW}${full_path}${NC}"

  # 1. Check if the target directory actually exists.
  if [ ! -d "$full_path" ]; then
    echo -e "${RED}Error: Directory not found: $full_path${NC}"
    echo "Skipping this entry."
    continue
  fi

  # 2. Check if a Dockerfile exists in that directory.
  if [ ! -f "$full_path/Dockerfile" ]; then
    echo -e "${RED}Error: Dockerfile not found in: $full_path${NC}"
    echo "Skipping this entry."
    continue
  fi

  # 3. Generate a Docker image tag from the final directory name.
  # This converts "DICOM/Dcmtk" to "dcmtk".
  # It first gets the basename ("Dcmtk") using shell parameter expansion.
  # Then, it converts the result to lowercase.
  # Note: The ",," for lowercase conversion requires Bash version 4.0 or newer.
  basename_only=${project##*/}
  image_tag=${basename_only,,}

  echo "Generated image tag: ${GREEN}${image_tag}${NC}"

  # 4. Change into the project directory.
  echo "Changing directory to $full_path"
  cd "$full_path"

  # 5. Build the Docker image.
  echo "Building Docker image..."
  docker build -t "$image_tag" .

  echo -e "${GREEN}Successfully built and tagged image: $image_tag${NC}"

  # Return to the starting directory for the next loop.
  cd "$START_DIR"
done

echo "--------------------------------------------------"
echo -e "${GREEN}All specified Docker images built successfully!${NC}"
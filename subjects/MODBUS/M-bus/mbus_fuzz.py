#!/usr/bin/env python3
"""
Manual, pipe‐driven Modbus TCP fuzzer demo. Sends one Read Coils request,
then a second with a mutated transaction ID.
"""

from boofuzz import *
import logging
import random
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

def write_to_pipe(pipe_path, message):
    """
    Write a single‐character command to the named pipe.
    """
    try:
        with open(pipe_path, 'w') as pipe:
            pipe.write(message)
            pipe.flush()
    except Exception as e:
        logger.error(f"Error writing to pipe '{pipe_path}': {e}")

def send_fuzzing_input(target_ip, target_port, data):
    """
    Send raw byte data to the target via TCP.
    """
    try:
        conn = TCPSocketConnection(target_ip, target_port)
        conn.open()
        logger.info(f"Sending {len(data)} bytes to {target_ip}:{target_port}")
        conn.send(data)
        conn.close()
    except Exception as e:
        logger.error(f"Failed to send fuzzing input: {e}")

def main():
    random.seed(1234)
    target_ip   = "127.0.0.1"
    target_port = 8502
    pipe_path   = "/tmp/dr_cov_cmd"

    # Define a single Modbus Read Coils request (function code 0x01)
    s_initialize("modbus_read_coils")
    # MBAP header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    # PDU
    s_byte(0x01)                # Function code: Read Coils
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of coils

    # Render the first (un-mutated) request
    req = s_get("modbus_read_coils")
    first = req.render()
    logger.info(f"Generated first test case (un-mutated): {len(first)} bytes")

    logger.info("Starting pipe protocol sequence")

    # First cycle: send 'F', request, wait, send 'D'
    logger.info("Sending 'F'")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending first fuzzing input")
    send_fuzzing_input(target_ip, target_port, first)
    time.sleep(0.1)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    # Second cycle: mutate the Transaction ID to 0x0002
    new_id = 0x0002
    id_bytes = new_id.to_bytes(2, 'big')
    mutated = id_bytes + first[2:]
    logger.info(f"Mutated Transaction ID to 0x{new_id:04x} for second send")

    logger.info("Sending 'F'")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending second fuzzing input (mutated)")
    send_fuzzing_input(target_ip, target_port, mutated)
    time.sleep(0.1)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')
    logger.info("Sending 'Q'")
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol sequence completed")

if __name__ == "__main__":
    main()
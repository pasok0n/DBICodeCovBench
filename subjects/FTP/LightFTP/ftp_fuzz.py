#!/usr/bin/env python3
"""
Demo FTP fuzzer with pipe‐driven manual control for a single STOR command.
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

def define_proto():
    """
    Define a minimal FTP protocol with USER, PASS, STOR, RETR.
    We will use only the STOR request for our manual sequence.
    """
    # USER <space> anonymous\r\n
    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    # PASS <space> james\r\n
    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    # STOR <space> AAAA\r\n  ← our fuzzing target
    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA", name="val")
    s_static("\r\n")

    # RETR <space> AAAA\r\n
    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

if __name__ == "__main__":
    random.seed(1234)
    target_ip   = "127.0.0.1"
    target_port = 2200
    pipe_path   = "/tmp/dr_cov_cmd"

    # Build the protocol definitions
    define_proto()

    # Generate the first (un‐mutated) STOR request
    first = s_get("stor").render()
    logger.info(f"Generated first test case (un‐mutated): {len(first)} bytes")

    logger.info("Starting pipe protocol sequence")

    # First cycle: send 'F', STOR packet, wait, send 'D'
    write_to_pipe(pipe_path, 'F')
    send_fuzzing_input(target_ip, target_port, first)
    time.sleep(0.5)
    write_to_pipe(pipe_path, 'D')

    # Generate second (mutated) STOR request by overwriting "AAAA" → "BBBB"
    sec = bytearray(first)
    # "STOR " is 5 bytes; the next 4 bytes are the filename "AAAA"
    sec[5:9] = b"BBBB"
    second = bytes(sec)
    logger.info(f"Generated second test case (mutated): {len(second)} bytes")

    # Second cycle: send 'F', mutated STOR, wait, send 'D', then 'Q'
    write_to_pipe(pipe_path, 'F')
    send_fuzzing_input(target_ip, target_port, second)
    time.sleep(0.5)
    write_to_pipe(pipe_path, 'D')
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol sequence completed")
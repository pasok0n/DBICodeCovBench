#!/usr/bin/env python3
"""
HTTP fuzzer with manual pipe‐driven control. Sends two variants of
a simple HTTP request via a TCPSocketConnection, coordinating with
an external tool over /tmp/dr_cov_cmd.
"""

from boofuzz import Request, Block, Group, Delim, String, Static, TCPSocketConnection
import logging
import random
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

def read_from_pipe(pipe_path):
    """
    Read a single character from the named pipe.
    """
    try:
        with open(pipe_path, 'r') as pipe:
            c = pipe.read(1)
            if not c:
                logger.warning(f"Pipe '{pipe_path}' closed or empty.")
                return ''
            return c
    except Exception as e:
        logger.error(f"Error reading from pipe '{pipe_path}': {e}")
        return ''

def write_to_pipe(pipe_path, msg):
    """
    Write a single‐character command to the named pipe.
    """
    try:
        with open(pipe_path, 'w') as pipe:
            pipe.write(msg)
            pipe.flush()
    except Exception as e:
        logger.error(f"Error writing to pipe '{pipe_path}': {e}")

def send_fuzzing_input(ip, port, data):
    """
    Send raw byte data to the target via TCP.
    """
    try:
        conn = TCPSocketConnection(ip, port)
        conn.open()
        logger.info(f"Sending {len(data)} bytes to {ip}:{port}")
        conn.send(data)
        conn.close()
    except Exception as e:
        logger.error(f"Failed to send fuzzing input: {e}")

def build_request():
    """
    Construct a basic HTTP request:
      GET /index.html HTTP/1.1\r\n
      Host: example.com\r\n
      \r\n
    """
    req = Request("HTTP-Request", children=(
        Block("Request-Line", children=(
            Group(name="Method", values=["GET"]),
            Delim(name="space-1", default_value=" "),
            String(name="URI", default_value="/index.html"),
            Delim(name="space-2", default_value=" "),
            String(name="Version", default_value="HTTP/1.1"),
            Static(name="CRLF", default_value="\r\n"),
        )),
        Block("Host-Line", children=(
            String(name="Host-Key", default_value="Host:"),
            Delim(name="space-3", default_value=" "),
            String(name="Host-Value", default_value="example.com"),
            Static(name="CRLF", default_value="\r\n"),
        )),
        Static(name="End-CRLF", default_value="\r\n"),
    ))
    return req

def main():
    random.seed(1234)
    target_ip   = "127.0.0.1"
    target_port = 8080
    pipe_path   = "/tmp/dr_cov_cmd"

    # Build and render the base request
    req = build_request()
    base = req.render()
    logger.info(f"Generated first test case: {len(base)} bytes")

    # First cycle: send F, base, wait, send D
    # logger.info("Waiting for 'P' from pipe")
    # if read_from_pipe(pipe_path) != 'P':
    #     return
    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')

    logger.info("Sending first request")
    send_fuzzing_input(target_ip, target_port, base)

    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    # Second cycle: wait for P, send F, send mutated, wait, send D, send Q
    # logger.info("Waiting for 'P' from pipe")
    # if read_from_pipe(pipe_path) != 'P':
    #     return
    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')

    # Mutate URI: "/index.html" → "/index_test"
    mutated = base.replace(b"/index.html", b"/index_test")
    logger.info("Sending second (mutated) request")
    send_fuzzing_input(target_ip, target_port, mutated)

    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    logger.info("Sending 'Q'")
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol sequence completed")

if __name__ == "__main__":
    main()
from boofuzz import *
import logging
import random
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

def write_to_pipe(pipe_path, message):
    """
    Write a single-character command to the named pipe.
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
    target_port = 8554
    pipe_path   = "/tmp/dr_cov_cmd"

    # Define RTSP OPTIONS request
    s_initialize("rtsp_options")
    s_string("OPTIONS")
    s_delim(" ")
    s_string(f"rtsp://{target_ip}:{target_port}/stream")
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    s_string("CSeq: ")
    s_string("1", name="cseq")
    s_delim("\r\n")
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    s_delim("\r\n")

    # Render the base (un-mutated) packet
    base = s_get("rtsp_options").render()
    logger.info(f"Generated base RTSP OPTIONS request: {len(base)} bytes")

    logger.info("Starting pipe protocol communication.")

    # First cycle
    logger.info("Received 'P'. Sending 'F'.")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending first fuzzing input.")
    send_fuzzing_input(target_ip, target_port, base)
    time.sleep(0.5)
    logger.info("Sending 'D'.")
    write_to_pipe(pipe_path, 'D')

    # Second cycle: mutate CSeq from "1" to "100"
    mutated = base.replace(b"CSeq: 1", b"CSeq: 100", 1)
    logger.info("Mutated CSeq for second send to 100.")

    logger.info("Received 'P'. Sending 'F'.")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending second fuzzing input (mutated).")
    send_fuzzing_input(target_ip, target_port, mutated)
    time.sleep(0.5)
    logger.info("Sending 'D'.")
    write_to_pipe(pipe_path, 'D')
    logger.info("Sending 'Q'.")
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol communication completed.")

if __name__ == "__main__":
    main()
from boofuzz import *
import logging
import random
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

def read_from_pipe(pipe_path):
    """
    Read a single character from the specified named pipe.
    """
    try:
        with open(pipe_path, 'r') as pipe:
            c = pipe.read(1)
            if not c:
                logger.warning(f"Pipe '{pipe_path}' closed or empty.")
                return ''
            return c
    except FileNotFoundError:
        logger.error(f"Pipe '{pipe_path}' not found.")
        return ''
    except Exception as e:
        logger.error(f"Error reading from pipe '{pipe_path}': {e}")
        return ''

def write_to_pipe(pipe_path, message):
    """
    Write a message to the specified named pipe.
    """
    try:
        with open(pipe_path, 'w') as pipe:
            pipe.write(message)
            pipe.flush()
    except FileNotFoundError:
        logger.error(f"Pipe '{pipe_path}' not found.")
    except Exception as e:
        logger.error(f"Error writing to pipe '{pipe_path}': {e}")

def send_fuzzing_input(target_ip, target_port, data):
    """
    Send the fuzzing input to the target over a UDP socket.
    """
    try:
        conn = UDPSocketConnection(target_ip, target_port)
        conn.open()
        logger.info(f"Sending {len(data)} bytes to {target_ip}:{target_port}")
        conn.send(data)
        conn.close()
    except Exception as e:
        logger.error(f"Failed to send fuzzing input: {e}")

def main():
    random.seed(1234)
    target_ip   = "127.0.0.1"
    target_port = 5353
    pipe_path   = "/tmp/dr_cov_cmd"

    # Define DNS A-query
    s_initialize("dns_query_a")
    s_word(0x1234,      name="transaction_id", endian=">")
    s_word(0x0100,      name="flags",          endian=">")
    s_word(0x0001,      name="qdcount",        endian=">")
    s_word(0x0000,      name="ancount",        endian=">")
    s_word(0x0000,      name="nscount",        endian=">")
    s_word(0x0000,      name="arcount",        endian=">")
    s_binary(
        "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00",
        name="qname"
    )
    s_word(0x0001,      name="qtype",          endian=">")
    s_word(0x0001,      name="qclass",         endian=">")

    # Generate first (un-mutated) packet
    req = s_get("dns_query_a")
    base = req.render()
    logger.info(f"Generated first (un-mutated) packet: {len(base)} bytes")

    logger.info("Starting pipe protocol communication")

    # First cycle
    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')

    logger.info("Sending first fuzzing input")
    send_fuzzing_input(target_ip, target_port, base)

    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    # Second cycle: manually mutate transaction ID in raw bytes
    new_id = 0x5678
    id_bytes = new_id.to_bytes(2, 'big')
    mutated = id_bytes + base[2:]
    logger.info(f"Mutated transaction_id to 0x{new_id:04x} for second send")

    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')

    logger.info("Sending second fuzzing input (mutated)")
    send_fuzzing_input(target_ip, target_port, mutated)

    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    logger.info("Sending 'Q'")
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol communication completed")

if __name__ == "__main__":
    main()
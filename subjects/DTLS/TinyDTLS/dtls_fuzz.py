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
    Send raw byte data to the target via UDP.
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
    target_port = 20220
    pipe_path   = "/tmp/dr_cov_cmd"

    # DTLS constants
    DTLS_1_0 = b"\xfe\xfd"
    DTLS_1_2 = b"\xfe\xff"
    HANDSHAKE = 22
    CLIENT_HELLO = 1

    # ------ DTLS ClientHello 1.0 ------
    s_initialize("dtls_client_hello_1_0")
    s_byte(HANDSHAKE,        name="record_type")
    s_bytes(DTLS_1_0,        name="protocol_version")
    s_word(0x0001,           name="epoch",             endian=">")
    s_qword(0x0000000000000001, name="sequence_number", endian=">")
    s_word(0x0040,           name="length",            endian=">")
    s_byte(CLIENT_HELLO,     name="handshake_type")
    s_bytes(b"\x00\x00\x3c", name="handshake_length")
    s_word(0x0000,           name="message_seq",       endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset")
    s_bytes(b"\x00\x00\x3c", name="fragment_length")
    s_bytes(DTLS_1_0,        name="client_version")
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time")
    s_bytes(b"\x00" * 28,    name="random_bytes")
    s_byte(0x00,             name="session_id_length")
    s_byte(0x00,             name="cookie_length")
    s_word(0x0004,           name="cipher_suites_length", endian=">")
    s_word(0xc02f,           name="cipher_suite1",       endian=">")
    s_word(0xc02b,           name="cipher_suite2",       endian=">")
    s_byte(0x01,             name="compression_methods_length")
    s_byte(0x00,             name="compression_method")
    s_word(0x0000,           name="extensions_length",    endian=">")

    # ------ DTLS ClientHello with invalid version ------
    s_initialize("dtls_client_hello_invalid_version")
    s_byte(HANDSHAKE,        name="record_type_inv")
    s_bytes(b"\xff\xff",     name="protocol_version_inv")
    s_word(0x0001,           name="epoch_inv",          endian=">")
    s_qword(0x0000000000000001, name="sequence_number_inv", endian=">")
    s_word(0x0040,           name="length_inv",         endian=">")
    s_byte(CLIENT_HELLO,     name="handshake_type_inv")
    s_bytes(b"\x00\x00\x3c", name="handshake_length_inv")
    s_word(0x0000,           name="message_seq_inv",    endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset_inv")
    s_bytes(b"\x00\x00\x3c", name="fragment_length_inv")
    s_bytes(b"\xff\xff",     name="client_version_inv")
    s_bytes(b"\x00\x00\x00\x00", name="gmt_time_inv")
    s_bytes(b"\x00" * 28,    name="random_bytes_inv")
    s_byte(0x00,             name="session_id_length_inv")
    s_byte(0x00,             name="cookie_length_inv")
    s_word(0x0004,           name="cipher_suites_length_inv", endian=">")
    s_word(0xc02f,           name="cipher_suite1_inv",        endian=">")
    s_word(0xc02b,           name="cipher_suite2_inv",        endian=">")
    s_byte(0x01,             name="compression_methods_length_inv")
    s_byte(0x00,             name="compression_method_inv")
    s_word(0x0000,           name="extensions_length_inv",     endian=">")

    # Generate raw packets
    pkt1 = s_get("dtls_client_hello_1_0").render()
    pkt2 = s_get("dtls_client_hello_invalid_version").render()

    logger.info(f"Generated first packet: {len(pkt1)} bytes")
    logger.info(f"Generated second packet: {len(pkt2)} bytes")

    # First cycle
    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending first DTLS ClientHello")
    send_fuzzing_input(target_ip, target_port, pkt1)
    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')

    # Second cycle
    logger.info("Received 'P'. Sending 'F'")
    write_to_pipe(pipe_path, 'F')
    logger.info("Sending mutated DTLS ClientHello (invalid version)")
    send_fuzzing_input(target_ip, target_port, pkt2)
    time.sleep(0.5)
    logger.info("Sending 'D'")
    write_to_pipe(pipe_path, 'D')
    logger.info("Sending 'Q'")
    write_to_pipe(pipe_path, 'Q')

    logger.info("Pipe protocol communication completed")

if __name__ == "__main__":
    main()
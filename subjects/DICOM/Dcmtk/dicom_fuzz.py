from boofuzz import *
import sys
import logging
import random
import os
import time

def read_from_pipe(pipe_path):
    try:
        with open(pipe_path, 'r') as pipe:
            c = pipe.read(1)
            if not c:
                logging.warning(f"Pipe '{pipe_path}' closed or empty.")
                return ''
            return c
    except FileNotFoundError:
        logging.error(f"Pipe '{pipe_path}' not found.")
        return ''
    except Exception as e:
        logging.error(f"Error reading from pipe '{pipe_path}': {e}")
        return ''

def write_to_pipe(pipe_path, msg):
    try:
        with open(pipe_path, 'w') as pipe:
            pipe.write(msg)
            pipe.flush()
    except FileNotFoundError:
        logging.error(f"Pipe '{pipe_path}' not found.")
    except Exception as e:
        logging.error(f"Error writing to pipe '{pipe_path}': {e}")

def send_fuzzing_input(ip, port, data):
    try:
        conn = TCPSocketConnection(ip, port)
        conn.open()
        logging.info(f"Sending {len(data)} bytes to {ip}:{port}")
        conn.send(data)
        conn.close()
    except Exception as e:
        logging.error(f"Failed to send fuzzing input: {e}")

def mutate_calling_ae_title(raw, new_title):
    """
    Overwrite the 16‐byte Calling AE Title field at offset 26.
    """
    ba = bytearray(raw)
    title_bytes = new_title.encode('ascii')
    ba[26:26+16] = title_bytes.ljust(16, b' ')
    return bytes(ba)

def main():
    random.seed(1234)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')

    target_ip   = "127.0.0.1"
    target_port = 5158
    pipe_path   = "/tmp/dr_cov_cmd"

    # Define A-ASSOCIATE-RQ
    s_initialize("dicom_associate_request")
    s_byte(0x01, name="pdu_type", fuzzable=True)
    s_byte(0x00, name="reserved1", fuzzable=False)
    # length of block below
    s_size("pdu_block", length=4, endian=">", name="pdu_length", fuzzable=True)

    with s_block("pdu_block"):
        s_word(0x0001, name="protocol_version", endian=">", fuzzable=True)
        s_bytes(b"\x00\x00", name="reserved2", fuzzable=False)
        s_string("DICOM-SCP",
                 size=16,
                 padding=b" ",
                 name="called_ae_title",
                 fuzzable=True)
        s_string("FUZZER",
                 size=16,
                 padding=b" ",
                 name="calling_ae_title",
                 fuzzable=True)
        s_bytes(b"\x00" * 32, name="reserved3", fuzzable=False)

        s_byte(0x20, name="pres_context_item_type", fuzzable=True)
        s_byte(0x00, name="pres_context_reserved1", fuzzable=False)
        s_size("pres_ctx", length=2, endian=">", fuzzable=True)
        with s_block("pres_ctx"):
            s_byte(0x01, name="pres_context_id", fuzzable=True)
            s_bytes(b"\x00\x00\x00", name="pres_context_reserved2", fuzzable=False)

            s_byte(0x30, name="abstract_syntax_item_type", fuzzable=True)
            s_byte(0x00, name="abstract_syntax_reserved", fuzzable=False)
            s_size("abs_syn", length=2, endian=">", fuzzable=True)
            with s_block("abs_syn"):
                s_string("1.2.840.10008.1.1",
                         name="abstract_syntax_uid",
                         fuzzable=True)

            s_byte(0x40, name="transfer_syntax_item_type", fuzzable=True)
            s_byte(0x00, name="transfer_syntax_reserved", fuzzable=False)
            s_size("trans_syn", length=2, endian=">", fuzzable=True)
            with s_block("trans_syn"):
                s_string("1.2.840.10008.1.2",
                         name="transfer_syntax_uid",
                         fuzzable=True)

    # Generate the base (un-mutated) packet
    req = s_get("dicom_associate_request")
    base = req.render()
    logging.info(f"Generated first (un-mutated) packet, {len(base)} bytes.")

    logging.info("Starting pipe protocol communication.")

    # First send
    # logger.info("Waiting for first 'P' from pipe...")
    # signal = read_from_pipe(pipe_path)
    # if signal == 'P':
    logging.info("Received 'P'. Sending 'F'.")
    write_to_pipe(pipe_path, 'F')

    logging.info("Sending first fuzzing input.")
    send_fuzzing_input(target_ip, target_port, base)

    logging.info("Waiting 0.5 seconds...")
    time.sleep(0.5)

    logging.info("Sending 'D'.")
    write_to_pipe(pipe_path, 'D')
    # else: abort...

    # Second send: mutate Calling AE Title in the raw bytes
    mutated = mutate_calling_ae_title(base, "FUZZER-MOD")
    logging.info("Mutated Calling AE Title to 'FUZZER-MOD' for second send.")

    # logger.info("Waiting for second 'P' from pipe...")
    # signal = read_from_pipe(pipe_path)
    # if signal == 'P':
    logging.info("Received 'P'. Sending 'F'.")
    write_to_pipe(pipe_path, 'F')

    logging.info("Sending second fuzzing input (mutated).")
    send_fuzzing_input(target_ip, target_port, mutated)

    logging.info("Waiting 0.5 seconds...")
    time.sleep(0.5)

    logging.info("Sending 'D'.")
    write_to_pipe(pipe_path, 'D')

    logging.info("Sending 'Q'.")
    write_to_pipe(pipe_path, 'Q')
    # else: abort...

    logging.info("Pipe protocol communication completed.")

if __name__ == "__main__":
    main()
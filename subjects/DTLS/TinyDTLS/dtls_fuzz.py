from boofuzz import *
import logging
import socket
import ssl
import time
import threading
import random

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    random.seed(1234)
    # DTLS server configuration
    target_ip = "127.0.0.1"  # Change to your target DTLS server IP
    target_port = 20220       # Common DTLS port, change if needed
    
    # Setup the session - DTLS uses UDP
    session = Session(
        target=Target(
            connection=UDPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.5,  # DTLS servers may need time to recover between tests
    )
    
    # DTLS Record Layer constants
    DTLS_1_0 = b"\xfe\xfd"  # DTLS 1.0 version bytes
    DTLS_1_2 = b"\xfe\xff"  # DTLS 1.2 version bytes
    
    # Record types
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    # Handshake types
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    
    # ------ DTLS ClientHello Message ------
    s_initialize("dtls_client_hello_1_0")
    
    # Record Header
    s_byte(HANDSHAKE, name="record_type")
    s_bytes(DTLS_1_0, name="protocol_version")
    s_word(0x0001, name="epoch", endian=">")
    s_qword(0x0000000000000001, name="sequence_number", endian=">")
    s_word(0x0040, name="length", endian=">")  # Length placeholder
    
    # Handshake Header
    s_byte(CLIENT_HELLO, name="handshake_type")
    s_bytes(b"\x00\x00\x3c", name="handshake_length")  # Length placeholder
    s_word(0x0000, name="message_seq", endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset")
    s_bytes(b"\x00\x00\x3c", name="fragment_length")  # Same as handshake length
    
    # ClientHello Fields
    s_bytes(DTLS_1_0, name="client_version")
    
    # Random (32 bytes)
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time")  # 4 bytes time
    s_bytes(b"\x00" * 28, name="random_bytes")          # 28 random bytes
    
    # Session ID
    s_byte(0x00, name="session_id_length")  # No session ID
    
    # Cookie
    s_byte(0x00, name="cookie_length")  # No cookie
    
    # Cipher Suites
    s_word(0x0004, name="cipher_suites_length", endian=">")  # 2 cipher suites
    s_word(0xc02f, name="cipher_suite1", endian=">")  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    s_word(0xc02b, name="cipher_suite2", endian=">")  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    
    # Compression Methods
    s_byte(0x01, name="compression_methods_length")
    s_byte(0x00, name="compression_method")  # null compression
    
    # Extensions Length
    s_word(0x0000, name="extensions_length", endian=">")  # No extensions
    
    # ------ DTLS ClientHello with DTLS 1.2 ------
    s_initialize("dtls_client_hello_1_2")
    
    # Record Header
    s_byte(HANDSHAKE, name="record_type_1_2")
    s_bytes(DTLS_1_2, name="protocol_version_1_2")
    s_word(0x0001, name="epoch_1_2", endian=">")
    s_qword(0x0000000000000001, name="sequence_number_1_2", endian=">")
    s_word(0x0040, name="length_1_2", endian=">")  # Length placeholder
    
    # Handshake Header
    s_byte(CLIENT_HELLO, name="handshake_type_1_2")
    s_bytes(b"\x00\x00\x3c", name="handshake_length_1_2")
    s_word(0x0000, name="message_seq_1_2", endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset_1_2")
    s_bytes(b"\x00\x00\x3c", name="fragment_length_1_2")
    
    # ClientHello Fields
    s_bytes(DTLS_1_2, name="client_version_1_2")
    
    # Random (32 bytes)
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time_1_2")
    s_bytes(b"\x00" * 28, name="random_bytes_1_2")
    
    # Session ID
    s_byte(0x00, name="session_id_length_1_2")
    
    # Cookie
    s_byte(0x00, name="cookie_length_1_2")
    
    # Cipher Suites
    s_word(0x0004, name="cipher_suites_length_1_2", endian=">")
    s_word(0xc02f, name="cipher_suite1_1_2", endian=">")
    s_word(0xc02b, name="cipher_suite2_1_2", endian=">")
    
    # Compression Methods
    s_byte(0x01, name="compression_methods_length_1_2")
    s_byte(0x00, name="compression_method_1_2")
    
    # Extensions Length
    s_word(0x0000, name="extensions_length_1_2", endian=">")
    
    # ------ DTLS ClientHello with invalid version ------
    s_initialize("dtls_client_hello_invalid_version")
    
    # Record Header
    s_byte(HANDSHAKE, name="record_type_invalid")
    s_bytes(b"\xff\xff", name="protocol_version_invalid")  # Invalid version
    s_word(0x0001, name="epoch_invalid", endian=">")
    s_qword(0x0000000000000001, name="sequence_number_invalid", endian=">")
    s_word(0x0040, name="length_invalid", endian=">")
    
    # Handshake Header
    s_byte(CLIENT_HELLO, name="handshake_type_invalid")
    s_bytes(b"\x00\x00\x3c", name="handshake_length_invalid")
    s_word(0x0000, name="message_seq_invalid", endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset_invalid")
    s_bytes(b"\x00\x00\x3c", name="fragment_length_invalid")
    
    # ClientHello with invalid version
    s_bytes(b"\xff\xff", name="client_version_invalid")
    
    # Random (32 bytes)
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time_invalid")
    s_bytes(b"\x00" * 28, name="random_bytes_invalid")
    
    # Rest of ClientHello structure
    s_byte(0x00, name="session_id_length_invalid")
    s_byte(0x00, name="cookie_length_invalid")
    s_word(0x0004, name="cipher_suites_length_invalid", endian=">")
    s_word(0xc02f, name="cipher_suite1_invalid", endian=">")
    s_word(0xc02b, name="cipher_suite2_invalid", endian=">")
    s_byte(0x01, name="compression_methods_length_invalid")
    s_byte(0x00, name="compression_method_invalid")
    s_word(0x0000, name="extensions_length_invalid", endian=">")
    
    # ------ DTLS ClientHello with large fragment offset ------
    s_initialize("dtls_client_hello_fragment_offset")
    
    # Record Header
    s_byte(HANDSHAKE, name="record_type_frag")
    s_bytes(DTLS_1_2, name="protocol_version_frag")
    s_word(0x0001, name="epoch_frag", endian=">")
    s_qword(0x0000000000000001, name="sequence_number_frag", endian=">")
    s_word(0x0040, name="length_frag", endian=">")
    
    # Handshake Header with large fragment offset
    s_byte(CLIENT_HELLO, name="handshake_type_frag")
    s_bytes(b"\x00\x00\x3c", name="handshake_length_frag")
    s_word(0x0000, name="message_seq_frag", endian=">")
    s_bytes(b"\xff\xff\xff", name="fragment_offset_frag")  # Very large offset
    s_bytes(b"\x00\x00\x3c", name="fragment_length_frag")
    
    # Rest of the ClientHello
    s_bytes(DTLS_1_2, name="client_version_frag")
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time_frag")
    s_bytes(b"\x00" * 28, name="random_bytes_frag")
    s_byte(0x00, name="session_id_length_frag")
    s_byte(0x00, name="cookie_length_frag")
    s_word(0x0004, name="cipher_suites_length_frag", endian=">")
    s_word(0xc02f, name="cipher_suite1_frag", endian=">")
    s_word(0xc02b, name="cipher_suite2_frag", endian=">")
    s_byte(0x01, name="compression_methods_length_frag")
    s_byte(0x00, name="compression_method_frag")
    s_word(0x0000, name="extensions_length_frag", endian=">")
    
    # ------ DTLS Alert Message ------
    s_initialize("dtls_alert")
    
    # Record Header
    s_byte(ALERT, name="alert_record_type")
    s_bytes(DTLS_1_2, name="alert_protocol_version")
    s_word(0x0001, name="alert_epoch", endian=">")
    s_qword(0x0000000000000001, name="alert_sequence_number", endian=">")
    s_word(0x0002, name="alert_length", endian=">")
    
    # Alert Level (1 = warning, 2 = fatal)
    s_byte(0x02, name="alert_level")
    
    # Alert Description (see TLS/DTLS specs for values)
    s_byte(0x28, name="alert_description")  # Handshake failure
    
    # ------ DTLS Change Cipher Spec Message ------
    s_initialize("dtls_change_cipher_spec")
    
    # Record Header
    s_byte(CHANGE_CIPHER_SPEC, name="ccs_record_type")
    s_bytes(DTLS_1_2, name="ccs_protocol_version")
    s_word(0x0001, name="ccs_epoch", endian=">")
    s_qword(0x0000000000000001, name="ccs_sequence_number", endian=">")
    s_word(0x0001, name="ccs_length", endian=">")
    
    # Change Cipher Spec message (always 1)
    s_byte(0x01, name="ccs_message")
    
    # ------ DTLS Application Data ------
    s_initialize("dtls_application_data")
    
    # Record Header
    s_byte(APPLICATION_DATA, name="app_record_type")
    s_bytes(DTLS_1_2, name="app_protocol_version")
    s_word(0x0001, name="app_epoch", endian=">")
    s_qword(0x0000000000000001, name="app_sequence_number", endian=">")
    s_word(0x0010, name="app_length", endian=">")
    
    # Application data (16 bytes)
    s_bytes(b"A" * 16, name="app_data")
    
    # ------ DTLS ClientHello with extremely large length fields ------
    s_initialize("dtls_client_hello_large_lengths")
    
    # Record Header with large length
    s_byte(HANDSHAKE, name="record_type_large")
    s_bytes(DTLS_1_2, name="protocol_version_large")
    s_word(0x0001, name="epoch_large", endian=">")
    s_qword(0x0000000000000001, name="sequence_number_large", endian=">")
    s_word(0xffff, name="length_large", endian=">")  # Maximum possible length
    
    # Handshake Header with large lengths
    s_byte(CLIENT_HELLO, name="handshake_type_large")
    s_bytes(b"\xff\xff\xff", name="handshake_length_large")  # Very large length
    s_word(0x0000, name="message_seq_large", endian=">")
    s_bytes(b"\x00\x00\x00", name="fragment_offset_large")
    s_bytes(b"\xff\xff\xff", name="fragment_length_large")  # Very large length
    
    # Basic ClientHello Fields
    s_bytes(DTLS_1_2, name="client_version_large")
    s_bytes(b"\x00\x00\x00\x00", name="gmt_unix_time_large")
    s_bytes(b"\x00" * 28, name="random_bytes_large")
    
    # Length fields with extreme values
    s_byte(0xff, name="session_id_length_large")  # Maximum 8-bit value
    s_bytes(b"\x00" * 255, name="session_id_large")  # Session ID data
    
    s_byte(0xff, name="cookie_length_large")  # Maximum 8-bit value
    s_bytes(b"\x00" * 255, name="cookie_large")  # Cookie data
    
    s_word(0xffff, name="cipher_suites_length_large", endian=">")  # Maximum 16-bit value
    s_bytes(b"\x00\x00" * 100, name="cipher_suites_large")  # Some cipher suites data (not full 65535)
    
    # ------ DTLS ClientHello with malformed record type ------
    s_initialize("dtls_malformed_record_type")
    
    # Record Header with invalid record type
    s_byte(0xff, name="invalid_record_type")  # Invalid record type
    s_bytes(DTLS_1_2, name="invalid_rt_protocol_version")
    s_word(0x0001, name="invalid_rt_epoch", endian=">")
    s_qword(0x0000000000000001, name="invalid_rt_sequence_number", endian=">")
    s_word(0x0040, name="invalid_rt_length", endian=">")
    
    # Rest is normal ClientHello
    s_byte(CLIENT_HELLO, name="invalid_rt_handshake_type")
    s_bytes(b"\x00\x00\x3c", name="invalid_rt_handshake_length")
    s_word(0x0000, name="invalid_rt_message_seq", endian=">")
    s_bytes(b"\x00\x00\x00", name="invalid_rt_fragment_offset")
    s_bytes(b"\x00\x00\x3c", name="invalid_rt_fragment_length")
    s_bytes(DTLS_1_2, name="invalid_rt_client_version")
    s_bytes(b"\x00\x00\x00\x00", name="invalid_rt_gmt_unix_time")
    s_bytes(b"\x00" * 28, name="invalid_rt_random_bytes")
    s_byte(0x00, name="invalid_rt_session_id_length")
    s_byte(0x00, name="invalid_rt_cookie_length")
    s_word(0x0004, name="invalid_rt_cipher_suites_length", endian=">")
    s_word(0xc02f, name="invalid_rt_cipher_suite1", endian=">")
    s_word(0xc02b, name="invalid_rt_cipher_suite2", endian=">")
    s_byte(0x01, name="invalid_rt_compression_methods_length")
    s_byte(0x00, name="invalid_rt_compression_method")
    s_word(0x0000, name="invalid_rt_extensions_length", endian=">")
    
    # Define the order in which to fuzz DTLS messages
    session.connect(s_get("dtls_client_hello_1_0"))
    session.connect(s_get("dtls_client_hello_1_2"))
    session.connect(s_get("dtls_client_hello_invalid_version"))
    session.connect(s_get("dtls_client_hello_fragment_offset"))
    session.connect(s_get("dtls_alert"))
    session.connect(s_get("dtls_change_cipher_spec"))
    session.connect(s_get("dtls_application_data"))
    session.connect(s_get("dtls_client_hello_large_lengths"))
    session.connect(s_get("dtls_malformed_record_type"))
    
    try:
        logger.info("Starting DTLS fuzzing session...")
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user")
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        return

if __name__ == "__main__":
    main()
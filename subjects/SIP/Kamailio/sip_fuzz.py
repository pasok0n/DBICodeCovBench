from boofuzz import *
import logging
import time
import random
import subprocess # Added for running external scripts

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def cleanup_server():
    """
    Executes the run_pjsip.sh script for server cleanup.
    """
    logger.info(
        "Performing server cleanup by running run_pjsip.sh..."
    )
    try:
        # Assuming run_pjsip.sh is executable and in the current directory or PATH.
        # If it requires specific arguments for cleanup (e.g., "stop", "cleanup"),
        # add them to the list: e.g., ["./run_pjsip.sh", "stop"]
        result = subprocess.run(
            ["./run_pjsip.sh"],
            capture_output=True,
            text=True,
            check=False, # Don't raise an exception on non-zero exit, log it instead
        )
        if result.stdout:
            logger.info(f"run_pjsip.sh stdout:\n{result.stdout}")
        if result.stderr:
            logger.error(f"run_pjsip.sh stderr:\n{result.stderr}")

        if result.returncode == 0:
            logger.info(
                "Server cleanup script executed successfully."
            )
        else:
            logger.warning(
                f"Server cleanup script run_pjsip.sh exited with code {result.returncode}."
            )
    except FileNotFoundError:
        logger.error(
            "Error: run_pjsip.sh script not found. "
            "Ensure it is in the current directory or system PATH and is executable."
        )
    except Exception as e:
        logger.error(f"An error occurred during server cleanup: {e}")

def main():
    random.seed(1234)
    # SIP server configuration
    target_ip = "127.0.0.1"  # Change to your target SIP server IP
    target_port = 5060       # Standard SIP port

    # Setup the session - SIP typically uses UDP
    session = Session(
        target=Target(
            connection=UDPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.5,  # Longer sleep between tests for SIP servers
    )
    cleanup_server()
    # Define a SIP REGISTER request
    s_initialize("sip_register")

    # Request Line
    s_string("REGISTER")
    s_delim(" ")
    s_string(f"sip:{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef")
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890")
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("12345678")
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1")
    s_delim(" ")
    s_string("REGISTER")
    s_delim("\r\n")

    s_string("Contact: ")
    s_string("<sip:fuzzer@127.0.0.1:5060>")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Expires: ")
    s_string("3600")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define a SIP INVITE request
    s_initialize("sip_invite")

    # Request Line
    s_string("INVITE")
    s_delim(" ")
    s_string(f"sip:user@{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef")
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890")
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:user@example.com>")
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("invitetest")
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1")
    s_delim(" ")
    s_string("INVITE")
    s_delim("\r\n")

    s_string("Contact: ")
    s_string("<sip:fuzzer@127.0.0.1:5060>")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    # SDP content
    s_string("Content-Type: application/sdp")
    s_delim("\r\n")

    # Calculate Content-Length based on SDP content
    sdp_content = (
        "v=0\r\n"
        + "o=fuzzer 123456 654321 IN IP4 127.0.0.1\r\n"
        + "s=Fuzz Call\r\n"
        + "c=IN IP4 127.0.0.1\r\n"
        + "t=0 0\r\n"
        + "m=audio 12345 RTP/AVP 0 8 101\r\n"
        + "a=rtpmap:0 PCMU/8000\r\n"
        + "a=rtpmap:8 PCMA/8000\r\n"
        + "a=rtpmap:101 telephone-event/8000\r\n"
        + "a=fmtp:101 0-16\r\n"
    )

    s_string("Content-Length: ")
    s_string(str(len(sdp_content)))
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # SDP content
    s_string(sdp_content)

    # Define a SIP OPTIONS request
    s_initialize("sip_options")

    # Request Line
    s_string("OPTIONS")
    s_delim(" ")
    s_string(f"sip:{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef")
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890")
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:options@example.com>")
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("optionstest")
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1")
    s_delim(" ")
    s_string("OPTIONS")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Accept: ")
    s_string("application/sdp")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define a SIP CANCEL request
    s_initialize("sip_cancel")

    # Request Line
    s_string("CANCEL")
    s_delim(" ")
    s_string(f"sip:user@{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef")
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890")
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:user@example.com>")
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("invitetest") # Should match the Call-ID of the INVITE it cancels
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1") # Should match the CSeq of the INVITE it cancels
    s_delim(" ")
    s_string("CANCEL") # Method in CSeq should be CANCEL
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define a SIP BYE request
    s_initialize("sip_bye")

    # Request Line
    s_string("BYE")
    s_delim(" ")
    s_string(f"sip:user@{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef") # Branch can be different for new requests in a dialog
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890") # From tag established in INVITE
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:user@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("abcdefghij") # To tag received from server in response to INVITE
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("invitetest") # Must match the dialog's Call-ID
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("2") # CSeq increments for new requests in a dialog
    s_delim(" ")
    s_string("BYE")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define a SIP ACK request
    s_initialize("sip_ack")

    # Request Line
    s_string("ACK")
    s_delim(" ")
    s_string(f"sip:user@{target_ip}") # Request-URI from To header of INVITE response
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK") # Should match branch of INVITE for non-2xx ACK
                               # For 2xx ACK, can be a new branch.
    s_string("deadbeef") # Using the same for simplicity in fuzzing template
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890") # From tag from INVITE
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:user@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("abcdefghij") # To tag from INVITE 2xx response
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("invitetest")
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1") # CSeq number from INVITE, method is ACK
    s_delim(" ")
    s_string("ACK")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define a malformed SIP request with excessive/invalid values
    s_initialize("sip_malformed")

    # Request Line with unusual method
    s_string("FUZZ")
    s_delim(" ")
    s_string(f"sip:{target_ip}")
    s_delim(" ")
    s_string("SIP/999.999")  # Invalid version
    s_delim("\r\n")

    # Malformed headers
    s_string("Via: SIP/2.0/XXX ")  # Invalid transport
    s_string("127.0.0.1:999999")   # Invalid port
    s_delim(";")
    s_string("branch=")
    s_string("A" * 1000)           # Excessively long branch
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:" + "A" * 1000 + "@example.com>")  # Excessively long username
    s_delim(";")
    s_string("tag=")
    s_string("1" * 1000)           # Excessively long tag
    s_delim("\r\n")

    s_string("To: ")
    s_string("<>")                 # Empty URI
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("A" * 1000)           # Excessively long Call-ID
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("999999999999")       # Excessive sequence number
    s_delim(" ")
    s_string("FUZZ")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("-1")                 # Invalid value
    s_delim("\r\n")

    s_string("Contact: ")
    s_string("<>")                 # Empty contact
    s_delim("\r\n")

    # Add some non-standard headers to test parsing
    s_string("X-Fuzz-Header: ")
    s_string("A" * 1000)
    s_delim("\r\n")

    # Invalid Content-Length, larger than actual content
    s_string("Content-Length: ")
    s_string("9999")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Small content to test Content-Length mismatch
    s_string("FUZZ")

    # Define a SIP SUBSCRIBE request
    s_initialize("sip_subscribe")

    # Request Line
    s_string("SUBSCRIBE")
    s_delim(" ")
    s_string(f"sip:{target_ip}")
    s_delim(" ")
    s_string("SIP/2.0")
    s_delim("\r\n")

    # Headers (required)
    s_string("Via: SIP/2.0/UDP ")
    s_string("127.0.0.1:5060")
    s_delim(";")
    s_string("branch=z9hG4bK")
    s_string("deadbeef")
    s_delim("\r\n")

    s_string("From: ")
    s_string("<sip:fuzzer@example.com>")
    s_delim(";")
    s_string("tag=")
    s_string("1234567890")
    s_delim("\r\n")

    s_string("To: ")
    s_string("<sip:subscribe@example.com>")
    s_delim("\r\n")

    s_string("Call-ID: ")
    s_string("subscribetest")
    s_string("@")
    s_string("localhost")
    s_delim("\r\n")

    s_string("CSeq: ")
    s_string("1")
    s_delim(" ")
    s_string("SUBSCRIBE")
    s_delim("\r\n")

    s_string("Contact: ")
    s_string("<sip:fuzzer@127.0.0.1:5060>")
    s_delim("\r\n")

    s_string("Max-Forwards: ")
    s_string("70")
    s_delim("\r\n")

    s_string("Event: ")
    s_string("presence")  # Event type
    s_delim("\r\n")

    s_string("Expires: ")
    s_string("3600")
    s_delim("\r\n")

    s_string("User-Agent: ")
    s_string("Boofuzz SIP Fuzzer")
    s_delim("\r\n")

    s_string("Content-Length: ")
    s_string("0")
    s_delim("\r\n")

    # End of headers
    s_delim("\r\n")

    # Define test case order - SIP sequence
    # First register, then other methods
    session.connect(s_get("sip_register"))
    session.connect(s_get("sip_options"))
    session.connect(s_get("sip_invite"))
    session.connect(s_get("sip_invite"), s_get("sip_cancel"))
    session.connect(s_get("sip_invite"), s_get("sip_ack")) # ACK is usually after 200 OK to INVITE
    # A more realistic flow might be INVITE -> (server 1xx) -> (server 200 OK) -> ACK
    # Then, later, BYE.
    # The current session.connect(s_get("sip_ack"), s_get("sip_bye")) implies ACK then BYE immediately.
    # This might be fine for fuzzing individual request handling.
    session.connect(s_get("sip_ack"), s_get("sip_bye")) # BYE is after a call is established (e.g. after ACK)
    session.connect(s_get("sip_subscribe"))
    session.connect(s_get("sip_malformed"))

    try:
        logger.info("Starting SIP fuzzing session...")
        session.fuzz()
        logger.info("Fuzzing session completed successfully.")
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user.")
        # The 'finally' block will execute before the function returns.
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        # The 'finally' block will execute before the function returns.
        return
    finally:
        logger.info(
            "Fuzzing process finished or was interrupted. Initiating server cleanup."
        )
        cleanup_server()


if __name__ == "__main__":
    main()

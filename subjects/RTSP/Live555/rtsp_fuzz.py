from boofuzz import *
import logging
import random
import string

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    random.seed(1234)
    # RTSP server configuration
    target_ip = "127.0.0.1"  # Change to your target RTSP server IP
    target_port = 8554        # Standard RTSP port
    
    # Setup the session - RTSP typically uses TCP
    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.5,  # Give RTSP server time to process each request,
        index_start=0,   # Start at the first test case
        index_end=1      # Stop after the first test case
    )
    
    # Define the stream URL to test
    # Typically something like rtsp://server/stream
    stream_path = "stream"  # Change this to a valid stream on your server
    rtsp_url = f"rtsp://{target_ip}:{target_port}/{stream_path}"
    
    # ------ Define RTSP OPTIONS request ------
    s_initialize("rtsp_options")
    
    # Request line
    s_string("OPTIONS")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("1")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP DESCRIBE request ------
    s_initialize("rtsp_describe")
    
    # Request line
    s_string("DESCRIBE")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("2")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    s_string("Accept: ")
    s_string("application/sdp")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP SETUP request ------
    s_initialize("rtsp_setup")
    
    # Request line
    s_string("SETUP")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("3")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # For RTP over UDP, client ports are typically 6970-6971
    s_string("Transport: ")
    s_string("RTP/AVP;unicast;client_port=6970-6971")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP PLAY request ------
    s_initialize("rtsp_play")
    
    # Request line
    s_string("PLAY")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("4")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # Session ID - this would normally be obtained from SETUP response
    # For fuzzing, we'll use a fixed one that might match a valid session
    s_string("Session: ")
    s_string("12345678")
    s_delim("\r\n")
    
    # Range header for specifying playback position
    s_string("Range: ")
    s_string("npt=0.000-")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP PAUSE request ------
    s_initialize("rtsp_pause")
    
    # Request line
    s_string("PAUSE")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("5")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # Session ID
    s_string("Session: ")
    s_string("12345678")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP TEARDOWN request ------
    s_initialize("rtsp_teardown")
    
    # Request line
    s_string("TEARDOWN")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("6")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # Session ID
    s_string("Session: ")
    s_string("12345678")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP GET_PARAMETER request ------
    s_initialize("rtsp_get_parameter")
    
    # Request line
    s_string("GET_PARAMETER")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("7")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # Session ID
    s_string("Session: ")
    s_string("12345678")
    s_delim("\r\n")
    
    # Content-Type
    s_string("Content-Type: ")
    s_string("text/parameters")
    s_delim("\r\n")
    
    # Parameter request
    parameter_body = "packets_received\nbytes_received\n"
    
    # Content-Length
    s_string("Content-Length: ")
    s_string(str(len(parameter_body)))
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # Body
    s_string(parameter_body)
    
    # ------ Define RTSP SET_PARAMETER request ------
    s_initialize("rtsp_set_parameter")
    
    # Request line
    s_string("SET_PARAMETER")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("8")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # Session ID
    s_string("Session: ")
    s_string("12345678")
    s_delim("\r\n")
    
    # Content-Type
    s_string("Content-Type: ")
    s_string("text/parameters")
    s_delim("\r\n")
    
    # Parameter setting
    parameter_body = "volume: 0.5\n"
    
    # Content-Length
    s_string("Content-Length: ")
    s_string(str(len(parameter_body)))
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # Body
    s_string(parameter_body)
    
    # ------ Define RTSP with malformed URL ------
    s_initialize("rtsp_malformed_url")
    
    # Request line with malformed URL
    s_string("OPTIONS")
    s_delim(" ")
    s_string("rtsp://" + "A" * 1000 + "@" + target_ip + ":" + str(target_port))
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("9")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP with invalid CSeq ------
    s_initialize("rtsp_invalid_cseq")
    
    # Request line
    s_string("OPTIONS")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers with invalid CSeq
    s_string("CSeq: ")
    s_string("-1")  # Negative value
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP with invalid version ------
    s_initialize("rtsp_invalid_version")
    
    # Request line with invalid RTSP version
    s_string("OPTIONS")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/9.9")  # Invalid version
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("10")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP with header injection attempt ------
    s_initialize("rtsp_header_injection")
    
    # Request line
    s_string("OPTIONS")
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers with injection attempt
    s_string("CSeq: ")
    s_string("11\r\nX-Injected-Header: injection")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # ------ Define RTSP with custom method ------
    s_initialize("rtsp_custom_method")
    
    # Request line with custom method
    s_string("FUZZ_METHOD")  # Non-standard method
    s_delim(" ")
    s_string(rtsp_url)
    s_delim(" ")
    s_string("RTSP/1.0")
    s_delim("\r\n")
    
    # Headers
    s_string("CSeq: ")
    s_string("12")
    s_delim("\r\n")
    
    s_string("User-Agent: ")
    s_string("Boofuzz-RTSP-Fuzzer")
    s_delim("\r\n")
    
    # End of headers
    s_delim("\r\n")
    
    # Define the order in which to fuzz RTSP endpoints
    # This follows the typical RTSP session flow
    session.connect(s_get("rtsp_options"))
    session.connect(s_get("rtsp_describe"))
    session.connect(s_get("rtsp_setup"))
    session.connect(s_get("rtsp_play"))
    session.connect(s_get("rtsp_pause"))
    session.connect(s_get("rtsp_get_parameter"))
    session.connect(s_get("rtsp_set_parameter"))
    session.connect(s_get("rtsp_teardown"))
    
    # Add the malformed requests after testing the standard flow
    session.connect(s_get("rtsp_malformed_url"))
    session.connect(s_get("rtsp_invalid_cseq"))
    session.connect(s_get("rtsp_invalid_version"))
    session.connect(s_get("rtsp_header_injection"))
    session.connect(s_get("rtsp_custom_method"))
    
    try:
        logger.info("Starting RTSP fuzzing session...")
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user")
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        return

if __name__ == "__main__":
    main()

from boofuzz import *
import logging
import time
import paramiko
import socket
import sys
import threading
import random
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SSH credentials
SSH_USERNAME = "ubuntu"
SSH_PASSWORD = "ubuntu"

# Flag to track if authentication succeeded
auth_success = False

# Function to attempt SSH authentication with the provided credentials
def test_ssh_auth(target_ip, target_port):
    global auth_success
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=target_ip,
            port=target_port,
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            timeout=5
        )
        auth_success = True
        logger.info(f"SSH authentication successful with {SSH_USERNAME}:{SSH_PASSWORD}")
        # Execute a simple command to verify shell access
        stdin, stdout, stderr = client.exec_command("echo 'SSH connection test'")
        response = stdout.read().decode()
        logger.info(f"SSH command response: {response.strip()}")
        client.close()
        return True
    except Exception as e:
        logger.error(f"SSH authentication failed: {e}")
        auth_success = False
        return False

# Process monitor that attempts to reconnect with valid credentials
class SSHProcessMonitor(threading.Thread):
    def __init__(self, target_ip, target_port):
        threading.Thread.__init__(self)
        self.target_ip = target_ip
        self.target_port = target_port
        self.daemon = True
        
    def run(self):
        while True:
            time.sleep(10)  # Check every 10 seconds
            try:
                test_ssh_auth(self.target_ip, self.target_port)
            except:
                pass

def main():
    random.seed(1234)
    # SSH server configuration
    target_ip = "127.0.0.1"  # Change to your target SSH server IP
    target_port = 22         # Standard SSH port
    
    # Test credentials first
    logger.info(f"Testing SSH credentials for {SSH_USERNAME} on {target_ip}:{target_port}")
    if not test_ssh_auth(target_ip, target_port):
        logger.warning("Initial authentication failed. Continuing with fuzzing anyway...")
    
    # Start the process monitor as a background thread
    monitor = SSHProcessMonitor(target_ip, target_port)
    monitor.start()
    
    # Define a simple restart function that will be called manually between tests
    def restart_target():
        logger.info("Attempting to reconnect to SSH server...")
        time.sleep(5)  # Wait for server to reset
        test_ssh_auth(target_ip, target_port)
        return
    
    # Setup the session
    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.5,
        restart_interval=50,  # Restart target every 50 test cases
        index_start=0,   # Start at the first test case
        index_end=1      # Stop after the first test case
    )
    
    # SSH identification string fuzzing
    s_initialize("ssh_identification")
    
    # SSH protocol requires that the first packet starts with "SSH-"
    # followed by protocol version and software information
    s_string("SSH-")
    s_string("2.0")  # Protocol version
    s_delim("-")
    s_string("Boofuzz_SSH_Fuzzer")  # Software ID
    s_delim("\r\n")
    
    # SSH malformed identification string
    s_initialize("ssh_malformed_identification")
    s_string("SSH-")
    s_string("999.999")  # Invalid protocol version
    s_delim("-")
    s_string("A" * 1000)  # Excessively long software ID
    s_delim("\r\n")
    
    # SSH identification with protocol confusion
    s_initialize("ssh_protocol_confusion")
    
    # Mix SSH with another protocol header to confuse the parser
    s_string("SSH-2.0-OpenSSH HTTP/1.1\r\nHost: localhost\r\n\r\n")
    
    # SSH identification with invalid line ending
    s_initialize("ssh_invalid_line_ending")
    s_string("SSH-2.0-Boofuzz_SSH_Fuzzer")
    s_string("\n")  # Missing CR (SSH requires CRLF)
    
    # SSH identification with null bytes
    s_initialize("ssh_null_bytes")
    s_string("SSH-2.0-Boofuzz")
    s_string("\x00\x00\x00\x00")  # Null bytes
    s_string("_Fuzzer")
    s_delim("\r\n")
    
    # SSH key exchange init packet fuzzing
    s_initialize("ssh_kex_init")
    
    # Packet length (4 bytes)
    s_dword(0x14, endian=">")  # 20 bytes for payload + padding
    
    # Padding length (1 byte)
    s_byte(0x04)  # 4 bytes of padding
    
    # Message code (1 byte) - 20 is SSH_MSG_KEXINIT
    s_byte(0x14)
    
    # 16 bytes of random cookie (used in key exchange)
    s_binary("00 00 00 00 00 01 00 00 00 00 10 00 00 10 00 00")
    
    # SSH packet with excessive padding
    s_initialize("ssh_excessive_padding")
    
    # Packet length (4 bytes)
    s_dword(0xFF, endian=">")  # Large packet
    
    # Padding length (1 byte)
    s_byte(0xFF)  # Maximum padding (invalid)
    
    # Message code (1 byte) - 20 is SSH_MSG_KEXINIT
    s_byte(0x14)
    
    # Some data to follow
    s_binary("00 00 00 11 01 00 10 00")
    
    # SSH invalid message type
    s_initialize("ssh_invalid_message")
    
    # Packet length (4 bytes)
    s_dword(0x0A, endian=">")  # 10 bytes
    
    # Padding length (1 byte)
    s_byte(0x04)  # 4 bytes of padding
    
    # Invalid message code (1 byte) - 0xFF is not a valid message type
    s_byte(0xFF)
    
    # Some data
    s_binary("00 01 00 00")
    
    # Fuzz with valid username/password format but malformed lengths
    s_initialize("ssh_userauth_request")
    
    # Packet length (4 bytes)
    s_dword(0x50, endian=">")  # Approximate length
    
    # Padding length (1 byte)
    s_byte(0x08)  # 8 bytes padding
    
    # Message code (1 byte) - 50 is SSH_MSG_USERAUTH_REQUEST
    s_byte(0x32)
    
    # Username length (4 bytes)
    s_dword(len(SSH_USERNAME), endian=">")
    
    # Username
    s_string(SSH_USERNAME)
    
    # Service name length (4 bytes)
    s_dword(0x0C, endian=">")  # 12 bytes
    
    # Service name: "ssh-connection"
    s_string("ssh-connection")
    
    # Auth method length (4 bytes)
    s_dword(0x08, endian=">")  # 8 bytes
    
    # Auth method: "password"
    s_string("password")
    
    # Boolean: FALSE (0)
    s_byte(0x00)
    
    # Password length (4 bytes)
    s_dword(len(SSH_PASSWORD), endian=">")
    
    # Password
    s_string(SSH_PASSWORD)
    
    # Channel fuzzing - simulating channel open
    s_initialize("ssh_channel_open")
    
    # Packet length (4 bytes)
    s_dword(0x40, endian=">")  # Approximate length
    
    # Padding length (1 byte)
    s_byte(0x08)  # 8 bytes padding
    
    # Message code (1 byte) - 90 is SSH_MSG_CHANNEL_OPEN
    s_byte(0x5A)
    
    # Channel type length (4 bytes)
    s_dword(0x07, endian=">")  # 7 bytes
    
    # Channel type: "session"
    s_string("session")
    
    # Sender channel (4 bytes)
    s_dword(0x00000001, endian=">")
    
    # Initial window size (4 bytes)
    s_dword(0x00100000, endian=">")  # 1MB
    
    # Maximum packet size (4 bytes)
    s_dword(0x00008000, endian=">")  # 32KB
    
    # Malformed SSH banner
    s_initialize("ssh_malformed_banner")
    s_string("NOT-SSH-2.0-Fuzzer\r\n")
    
    # SSH version with special characters
    s_initialize("ssh_special_chars")
    s_string("SSH-2.0-Fuzzer!@#$%^&*()_+<>?:\"{}|\r\n")
    
    # SSH version with extra data
    s_initialize("ssh_extra_data")
    s_string("SSH-2.0-Fuzzer\r\n\r\nEXTRA DATA THAT SHOULD BE IGNORED\r\n")
    
    # Define the order in which to fuzz SSH messages
    session.connect(s_get("ssh_identification"))
    session.connect(s_get("ssh_malformed_identification"))
    session.connect(s_get("ssh_protocol_confusion"))
    session.connect(s_get("ssh_invalid_line_ending"))
    session.connect(s_get("ssh_null_bytes"))
    session.connect(s_get("ssh_malformed_banner"))
    session.connect(s_get("ssh_special_chars"))
    session.connect(s_get("ssh_extra_data"))
    
    # Binary packet fuzzing
    session.connect(s_get("ssh_kex_init"))
    session.connect(s_get("ssh_excessive_padding"))
    session.connect(s_get("ssh_invalid_message"))
    
    # Authentication fuzzing (using the provided credentials)
    session.connect(s_get("ssh_userauth_request"))
    
    # Channel fuzzing
    session.connect(s_get("ssh_channel_open"))
    
    try:
        logger.info("Starting SSH fuzzing session...")
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user")
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        return

if __name__ == "__main__":
    main()

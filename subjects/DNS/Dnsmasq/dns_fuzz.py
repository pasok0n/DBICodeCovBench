from boofuzz import *
import logging
import binascii
import random

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    random.seed(1234)
    # DNS server configuration
    target_ip = "127.0.0.1"  # Change to your target DNS server IP
    target_port = 5353         # Standard DNS port
    
    # Setup the session for UDP (most common for DNS)
    session = Session(
        target=Target(
            connection=UDPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.1,
        index_start=0,   # Start at the first test case
        index_end=1      # Stop after the first test case
    )
    
    # Define DNS header format
    s_initialize("dns_query_a")
    
    # Transaction ID (16 bits)
    s_word(0x1234, endian=">")
    
    # Flags (16 bits)
    # 0x0100: Standard query with recursion desired
    s_word(0x0100, endian=">")
    
    # QDCOUNT: Number of questions (16 bits)
    s_word(0x0001, endian=">")
    
    # ANCOUNT: Number of answers (16 bits)
    s_word(0x0000, endian=">")
    
    # NSCOUNT: Number of authority records (16 bits)
    s_word(0x0000, endian=">")
    
    # ARCOUNT: Number of additional records (16 bits)
    s_word(0x0000, endian=">")
    
    # DNS Question section
    # QNAME: Domain name to query (length-prefixed format)
    # For example, "example.com" becomes "\x07example\x03com\x00"
    # Convert to hex string representation
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    
    # QTYPE: Query type (16 bits) - 0x0001 is A record
    s_word(0x0001, endian=">")
    
    # QCLASS: Query class (16 bits) - 0x0001 is IN (Internet)
    s_word(0x0001, endian=">")
    
    # Initialize other query types
    s_initialize("dns_query_aaaa")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    # 0x001c is AAAA record
    s_word(0x001c, endian=">")
    s_word(0x0001, endian=">")
    
    # MX record query
    s_initialize("dns_query_mx")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    # 0x000f is MX record
    s_word(0x000f, endian=">")
    s_word(0x0001, endian=">")
    
    # TXT record query
    s_initialize("dns_query_txt")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    # 0x0010 is TXT record
    s_word(0x0010, endian=">")
    s_word(0x0001, endian=">")
    
    # SOA record query
    s_initialize("dns_query_soa")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    # 0x0006 is SOA record
    s_word(0x0006, endian=">")
    s_word(0x0001, endian=">")
    
    # ANY query (can return all record types)
    s_initialize("dns_query_any")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    # 0x00ff is ANY
    s_word(0x00ff, endian=">")
    s_word(0x0001, endian=">")
    
    # Create a long domain name query to test buffer overflow possibilities
    s_initialize("dns_query_long_domain")
    s_word(0x1234, endian=">")
    s_word(0x0100, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    
    # Generate a long domain with many subdomains (30 segments)
    long_domain = "03 73 75 62 " * 30 + "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00"
    s_binary(long_domain)
    s_word(0x0001, endian=">")
    s_word(0x0001, endian=">")
    
    # Create DNS queries with various flags
    s_initialize("dns_query_flags")
    s_word(0x1234, endian=">")
    # Set all bits in the flags field to fuzz DNS server behavior
    s_word(0xffff, endian=">")
    s_word(0x0001, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_word(0x0000, endian=">")
    s_binary("07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
    s_word(0x0001, endian=">")
    s_word(0x0001, endian=">")
    
    # Define test case order - test all query types
    session.connect(s_get("dns_query_a"))
    session.connect(s_get("dns_query_aaaa"))
    session.connect(s_get("dns_query_mx"))
    session.connect(s_get("dns_query_txt"))
    session.connect(s_get("dns_query_soa"))
    session.connect(s_get("dns_query_any"))
    session.connect(s_get("dns_query_long_domain"))
    session.connect(s_get("dns_query_flags"))
    
    try:
        logger.info("Starting DNS fuzzing session...")
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user")
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        return

if __name__ == "__main__":
    main()
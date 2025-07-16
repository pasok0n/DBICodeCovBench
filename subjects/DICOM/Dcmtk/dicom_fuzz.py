from boofuzz import *
import sys
import logging
import random

def main():
    random.seed(1234)
    # DICOM server configuration
    target_ip = "127.0.0.1"  # Change to your target DICOM server IP
    target_port = 5158        # Default DICOM port, modify if necessary
    
    # Setup the session
    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.1  # Adjust sleep time between test cases
    )

    # Define the DICOM A-ASSOCIATE-RQ PDU
    s_initialize("dicom_associate_request")
    
    # PDU Type (0x01 for A-ASSOCIATE-RQ)
    s_byte(0x01, name="pdu_type", fuzzable=True)
    # Reserved byte
    s_byte(0x00, name="reserved1", fuzzable=False)
    # PDU Length field (will be calculated automatically)
    s_size("pdu_body", length=4, endian=">", fuzzable=True)
    
    with s_block("pdu_body"):
        # Protocol Version
        s_word(0x0001, name="protocol_version", endian=">", fuzzable=True)
        # Reserved bytes
        s_bytes(b"\x00\x00", name="reserved2", fuzzable=False)
        # Called AE Title (Service Provider)
        s_string("DICOM-SCP", size=16, padding=b" ", name="called_ae_title", fuzzable=True)
        # Calling AE Title (Service User)
        s_string("FUZZER", size=16, padding=b" ", name="calling_ae_title", fuzzable=True)
        # Reserved bytes
        s_bytes(b"\x00" * 32, name="reserved3", fuzzable=False)
        
        # Presentation Context Item
        s_byte(0x20, name="pres_context_item_type", fuzzable=True)
        s_byte(0x00, name="pres_context_reserved1", fuzzable=False)
        s_size("pres_context_body", length=2, endian=">", fuzzable=True)
        
        with s_block("pres_context_body"):
            # Presentation Context ID
            s_byte(0x01, name="pres_context_id", fuzzable=True)
            # Reserved bytes
            s_bytes(b"\x00\x00\x00", name="pres_context_reserved2", fuzzable=False)
            
            # Abstract Syntax Sub-item
            s_byte(0x30, name="abstract_syntax_item_type", fuzzable=True)
            s_byte(0x00, name="abstract_syntax_reserved", fuzzable=False)
            s_size("abstract_syntax_body", length=2, endian=">", fuzzable=True)
            
            with s_block("abstract_syntax_body"):
                # Verification SOP Class UID
                s_string("1.2.840.10008.1.1", name="abstract_syntax_uid", fuzzable=True)
            
            # Transfer Syntax Sub-item
            s_byte(0x40, name="transfer_syntax_item_type", fuzzable=True)
            s_byte(0x00, name="transfer_syntax_reserved", fuzzable=False)
            s_size("transfer_syntax_body", length=2, endian=">", fuzzable=True)
            
            with s_block("transfer_syntax_body"):
                # Implicit VR Little Endian Transfer Syntax UID
                s_string("1.2.840.10008.1.2", name="transfer_syntax_uid", fuzzable=True)
    
    # Define a simple DICOM C-ECHO request
    s_initialize("dicom_c_echo")
    s_byte(0x04, name="echo_pdu_type")  # C-ECHO-RQ PDU type
    s_byte(0x00, name="echo_reserved")
    s_size("echo_body", length=4, endian=">")
    
    with s_block("echo_body"):
        # Add the appropriate C-ECHO command elements
        s_bytes(b"\x00\x00\x00\x00", name="command_length")
        s_bytes(b"\x00\x00\x00\x30", name="command_field")  # C-ECHO-RQ
        s_bytes(b"\x00\x00\x00\x00", name="message_id")
        s_bytes(b"\x00\x00\x00\x00", name="data_set_type")  # No dataset
    
    # Add the requests to the session - first associate, then echo
    session.connect(s_get("dicom_associate_request"))
    session.connect(s_get("dicom_c_echo"))
    
    try:
        session.fuzz()
    except KeyboardInterrupt:
        return
    except Exception as e:
        return

if __name__ == "__main__":
    main()
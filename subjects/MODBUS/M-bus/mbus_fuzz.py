from boofuzz import *
import logging
import random

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    random.seed(1234)
    # Modbus server configuration
    target_ip = "127.0.0.1"  # Change to your target Modbus server IP
    target_port = 8502        # Standard Modbus TCP port
    
    # Setup the session
    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_ip, target_port)
        ),
        sleep_time=0.1,  # Adjust sleep time between test cases
        index_start=0,   # Start at the first test case
        index_end=1      # Stop after the first test case
    )

    # ----- Read Coils (0x01) -----
    s_initialize("modbus_read_coils")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID (always 0 for Modbus TCP)
    s_word(0x0006, endian=">")  # Length (6 bytes to follow)
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x01)                # Function code (0x01 = Read Coils)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of coils (1-2000)

    # ----- Read Discrete Inputs (0x02) -----
    s_initialize("modbus_read_discrete_inputs")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x02)                # Function code (0x02 = Read Discrete Inputs)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of inputs (1-2000)

    # ----- Read Holding Registers (0x03) -----
    s_initialize("modbus_read_holding_registers")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x03)                # Function code (0x03 = Read Holding Registers)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of registers (1-125)

    # ----- Read Input Registers (0x04) -----
    s_initialize("modbus_read_input_registers")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x04)                # Function code (0x04 = Read Input Registers)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of registers (1-125)

    # ----- Write Single Coil (0x05) -----
    s_initialize("modbus_write_single_coil")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x05)                # Function code (0x05 = Write Single Coil)
    s_word(0x0000, endian=">")  # Output Address
    s_word(0xFF00, endian=">")  # Output Value (FF00 = ON, 0000 = OFF)

    # ----- Write Single Register (0x06) -----
    s_initialize("modbus_write_single_register")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x06)                # Function code (0x06 = Write Single Register)
    s_word(0x0000, endian=">")  # Register Address
    s_word(0x1234, endian=">")  # Register Value

    # ----- Write Multiple Coils (0x0F) -----
    s_initialize("modbus_write_multiple_coils")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0009, endian=">")  # Length (9 bytes to follow)
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x0F)                # Function code (0x0F = Write Multiple Coils)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0008, endian=">")  # Quantity of coils (8 coils)
    s_byte(0x01)                # Byte count (1 byte)
    s_byte(0xFF)                # Coil values (all 8 coils ON)

    # ----- Write Multiple Registers (0x10) -----
    s_initialize("modbus_write_multiple_registers")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x000B, endian=">")  # Length (11 bytes to follow)
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x10)                # Function code (0x10 = Write Multiple Registers)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0002, endian=">")  # Quantity of registers (2 registers)
    s_byte(0x04)                # Byte count (4 bytes)
    s_word(0x1234, endian=">")  # First register value
    s_word(0x5678, endian=">")  # Second register value

    # ----- Fuzz with invalid function code -----
    s_initialize("modbus_invalid_function")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU with invalid function code
    s_byte(0xFF)                # Invalid function code (0xFF)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity

    # ----- Diagnostic (0x08) with various sub-functions -----
    s_initialize("modbus_diagnostic")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x08)                # Function code (0x08 = Diagnostics)
    s_word(0x0000, endian=">")  # Sub-function (0x0000 = Return Query Data)
    s_word(0x1234, endian=">")  # Data

    # ----- Fuzz with excessive register request -----
    s_initialize("modbus_excessive_registers")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0x0000, endian=">")  # Protocol ID
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x03)                # Function code (0x03 = Read Holding Registers)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0xFFFF, endian=">")  # Excessive quantity of registers (beyond spec limit)

    # ----- Fuzz with invalid protocol ID -----
    s_initialize("modbus_invalid_protocol")
    
    # MBAP Header
    s_word(0x0001, endian=">")  # Transaction ID
    s_word(0xFFFF, endian=">")  # Invalid Protocol ID (should be 0)
    s_word(0x0006, endian=">")  # Length
    s_byte(0x01)                # Unit ID
    
    # PDU
    s_byte(0x03)                # Function code (0x03 = Read Holding Registers)
    s_word(0x0000, endian=">")  # Starting Address
    s_word(0x0001, endian=">")  # Quantity of registers
    
    # Define the order to fuzz the different Modbus requests
    session.connect(s_get("modbus_read_coils"))
    session.connect(s_get("modbus_read_discrete_inputs"))
    session.connect(s_get("modbus_read_holding_registers"))
    session.connect(s_get("modbus_read_input_registers"))
    session.connect(s_get("modbus_write_single_coil"))
    session.connect(s_get("modbus_write_single_register"))
    session.connect(s_get("modbus_write_multiple_coils"))
    session.connect(s_get("modbus_write_multiple_registers"))
    session.connect(s_get("modbus_invalid_function"))
    session.connect(s_get("modbus_diagnostic"))
    session.connect(s_get("modbus_excessive_registers"))
    session.connect(s_get("modbus_invalid_protocol"))
    
    try:
        logger.info("Starting Modbus fuzzing session...")
        session.fuzz()
    except KeyboardInterrupt:
        logger.info("Fuzzing session interrupted by user")
        return
    except Exception as e:
        logger.error(f"Error during fuzzing: {e}")
        return

if __name__ == "__main__":
    main()
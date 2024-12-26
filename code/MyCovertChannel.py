import scapy.utils
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPHeader

from itertools import takewhile, cycle
from zlib import compress, decompress
from random import choice
from datetime import datetime

from CovertChannelBase import CovertChannelBase
from scapy.all import *

def get_field_bytes(pkt: NTPHeader, name):
    fld, val = pkt.getfield_and_val(name)
    return fld.addfield(pkt, b"", val)

def get_ntp_timestamp(ntp_epoch: int, hidden_data: int = 0) -> int:
    unix_time = time.time()
    ntp_time = unix_time + ntp_epoch
    seconds = int(ntp_time)

    timestamp = (seconds << 32) | hidden_data
    return timestamp

def send_integer(integer: int, sender_func, ntp_epoch: int):
    # TODO encode integer
    current_ntp_timestamp = get_ntp_timestamp(ntp_epoch, integer)
    timestamp_with_hidden_data = current_ntp_timestamp.to_bytes(8, byteorder='big')

    ntp_data = (
            b'\x1b' +  # LI (0), Version (3), Mode (3 - Client)
            b'\x10\xf6\x00' +  # Stratum, Poll, Precision
            b'\x00\x00\x00\x00' +  # Root Delay TODO set to realistic value
            b'\x00\x00\x00\x00' +  # Root Dispersion TODO set to realistic value
            b'LOCL' +  # Reference Identifier
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # Reference Timestamp
            timestamp_with_hidden_data +  # Originate Timestamp
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # Receive Timestamp
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Transmit Timestamp
    )

    ntp_packet = IP(dst="receiver") / UDP(sport=123, dport=123) / Raw(load=ntp_data)
    #ntp_packet.show()
    sender_func(ntp_packet)

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251]

MUL_OF_5 = [10, 15, 20, 25, 30, 40, 45, 50, 55, 60, 75, 80, 85, 90, 95, 100, 110, 115, 120, 125, 135, 145, 150, 155, 160, 165, 170, 180, 185, 190, 200, 205, 215, 220, 225, 230, 235, 240, 250, 255]

MUL_OF_7 = [14, 21, 28, 42, 49, 56, 63, 77, 84, 98, 112, 119, 126, 133, 147, 154, 161, 168, 189, 196, 203, 217, 224, 231, 238, 252]

MUL_OF_13 = [26, 39, 52, 78, 104, 117, 143, 156, 169, 208, 221, 234, 247]



def get_2_bits(value: int) -> int:
    """
    Takes a byte, gives 2 bits
    """
    if value in PRIMES:
        return 0
    elif value in MUL_OF_5:
        return 1
    elif value in MUL_OF_7:
        return 2
    elif value in MUL_OF_13:
        return 3
    return 0

def make_byte(value: int) -> int:
    """
    Takes 2 bits, gives a byte
    """
    if value == 0:
        return choice(PRIMES)
    elif value == 1:
        return choice(MUL_OF_5)
    elif value == 2:
        return choice(MUL_OF_7)
    elif value == 3:
        return choice(MUL_OF_13)
    return 0

def get_byte(values: list[int]) -> int:
    """
    Takes 4 bytes, gives 1 byte
    """
    bit_pairs = [get_2_bits(v) for v in values]
    val = bit_pairs[0] | (bit_pairs[1] << 2) | (bit_pairs[2] << 4) | (bit_pairs[3] << 6)
    return val
    
def make_bytes(value: int) -> list[int]:
    """
    Takes 1 byte, gives 4 bytes
    """
    bit_pairs = (value & 0x3, (value >> 2) & 0x3, (value >> 4) & 0x3, (value >> 6) & 0x3)
    return [make_byte(p) for p in bit_pairs]

def encode_bit_pairs(message: bytes) -> bytes:
    integers = [value for b in message for value in make_bytes(b)]
    ret = bytes(integers)
    return ret

def decode_bit_pairs(message: bytes) -> bytes:
    integers = [b for b in message]
    grouped = [integers[i:i+4] for i in range(0, len(integers), 4)]
    as_byte_integers = [get_byte(g) for g in grouped]
    ret = bytes(as_byte_integers)
    return ret

def encode_xor(message: bytes, key: int) -> bytes:
    encoder = cycle(int.to_bytes(key, 4, byteorder='big'))
    ret = bytes(a ^ b for a,b in zip(message, encoder))
    return ret

def decode_xor(message: bytes, key: int) -> bytes:
    return encode_xor(message, key) # XOR is symmetric

def encode(message: bytes, key: int) -> bytes:
    return encode_xor(message, key)

def decode(message: bytes, key: int) -> bytes:
    return decode_xor(message, key)

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        self.precision = 0
        self.data = b''
        self.finished = False
    def send(self, log_file_name, ntp_epoch, key, finisher):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 128, 128)[:-8]
        with open('times.txt', 'w') as f:
            f.write(str(datetime.now().timestamp()) + '\n')
        byte_message = bytes(
            takewhile(
                lambda x: x != ord('.'),
                int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big')
            )
        )
        byte_message = encode(byte_message, key)
        
        byte_message = byte_message + str.encode(finisher)
        extra_bytes_number = len(byte_message) % 4;
        padding_size = (4 - extra_bytes_number) % 4;
        old_len = len(byte_message)
        byte_message = byte_message + (b'\x00' * padding_size)
        for i in range(0, len(byte_message), 4):
            number = int.from_bytes(byte_message[i:i+4], byteorder='big')
            send_integer(number, super().send, ntp_epoch)
        # TODO encode message

    def receive(self, log_file_name, ntp_epoch, key, finisher):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        def process_packet(received_packet: Packet):
            nonlocal ntp_epoch
            if UDP in received_packet and received_packet[UDP].dport == 123 and received_packet[IP].src != "172.18.0.3":
                client_port = received_packet[UDP].sport

                ref_timestamp_bytes = get_field_bytes(received_packet[NTPHeader], "orig")
                rightmost_bytes = ref_timestamp_bytes[-4:]
                written = bytes(takewhile(lambda x: x != ord(finisher), rightmost_bytes))
                written = rightmost_bytes
                self.data = self.data + written
                if ord(finisher) in written:
                    start_stamp = 0.0
                    self.data = self.data
                    with open('times.txt', 'r') as f:
                        start_stamp = float(f.read())
                    with open('times.txt', 'w') as f:
                        stop_stamp = datetime.now().timestamp()
                        throughput = (len(self.data) + 1) / (stop_stamp - start_stamp)
                        f.write(str(throughput))
                    with open(log_file_name, 'wb') as f:
                        decoded = decode(bytes(takewhile(lambda x: x != ord(finisher), self.data)), key)
                        f.write(decoded + b'.')
                    self.finished = True

                ntp_response = b'\x1c' + (  # LI=0, Version=4, Mode=4 (Server)
                        b'\x0E'  # Stratum 2 (secondary server)
                        b'\x06'  # Poll interval
                        b'\xFA'  # Precision
                        b'\x00\x00\x00\x00'  # Root Delay
                        b'\x00\x00\x00\x00'  # Root Dispersion
                        b'LOCL'  # Reference Identifier (e.g., Local clock)
                        + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Reference Timestamp
                        + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Originate Timestamp
                        + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Receive Timestamp
                        + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Transmit Timestamp
                )

                response_packet = (
                        IP(dst="sender", src="receiver") /
                        UDP(sport=123, dport=client_port) /
                        Raw(load=ntp_response)
                )

                # to make it look realistic
                send(response_packet, verbose=0)
           
        sniff(filter="udp port 123", prn=process_packet, store=False, stop_filter=lambda x: self.finished)

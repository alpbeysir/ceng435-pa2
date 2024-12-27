from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPHeader

from itertools import takewhile, cycle
from zlib import compress, decompress
from random import choice
from datetime import datetime
from typing import Optional
from functools import cache
from math import ceil, log2

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

def send_integer(integer: int, sender_func, ntp_epoch: int, port: int):
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

    ntp_packet = IP(dst="receiver") / UDP(sport=port, dport=port) / Raw(load=ntp_data)
    sender_func(ntp_packet)

@cache
def is_prime(n: int) -> bool:
    global PRIMES
    max_factor = int(n ** 0.5)
    for num in range(2, max_factor+1):
        if n % num == 0:
            return False
    return True
    
def make_byte(value: int, groups: list[list[int]]) -> int:
    """
    Convert ceil(log2(len(groups))) bits and convert it to a single byte.

    :param value: The value to be converted into a byte.
    :param groups: The group partitions to be used to convert the bits to a byte.
    :returns: Single byte encoding the value
    """

    # Get random
    return choice(groups[value])
def make_bytes(value: int, bit_count: int, groups: list[list[int]]) -> list[int]:
    """
    Convert a byte into multiple bytes. Takes 1 byte, gives ceil(8 / bit_count) bytes.

    :param value: The value to be converted to multiple bytes.
    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to convert the value to multiple bytes.
    :returns: Multiple bytes encoding the value.
    """

    # bit_count 1s
    mask = (2 ** bit_count) - 1

    # Number of encoded bits is ceil(8 / bit_count)
    ret = []
    for i in range(int(ceil(8 / bit_count))):
        # Append the bit_count bits from the value
        ret.append(value & mask)

        # Shift right to get the next bit_count bits
        value = value >> bit_count
    
    # Encode each bit group into bytes corresponding to the groups
    return [make_byte(p, groups) for p in ret]
def encode_bit_pairs(message: bytes, bit_count: int, groups: list[list[int]]) -> bytes:
    """
    Encodes a message using groups.

    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to encode the message.
    :returns: The encoded message.
    """

    integers = [
        value
        for b in message # Each byte in the message
        for value in make_bytes(b, bit_count, groups) # converted to multiple bytes. Take each value in this multiple byte array
    ]

    # integers is an integer array with each value being a byte of the encoded message, which can be converted to a bytes object
    ret = bytes(integers)
    return ret


def get_bits(value: int, groups: list[list[int]]) -> int:
    """
    Takes a byte, gives 2 bits
    """
    for (i, g) in enumerate(groups):
        if value in g:
            return i
    return 0
def get_byte(values: list[int], bit_count: int, groups: list[list[int]]) -> int:
    """
    Convert multiple bytes into a single byte. Takes ceil(8 / bit_count) bytes, gives 1 byte.

    :param values: The byte values to be converted into one byte.
    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to convert the value to a single byte.
    """

    # Get the bits
    bit_groups = [get_bits(v, groups) for v in values]
    ret = 0
    for g in reversed(bit_groups):
        ret = ret << bit_count
        ret = ret | g
    return ret
def decode_bit_pairs(message: bytes, bit_count: int, groups: list[list[int]]) -> bytes:
    """
    Decodes a message using groups.

    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to decode the message.
    :returns: The decoded message.
    """

    # Convert the bytes into integer array
    integers = [b for b in message]

    # The number of the bit groups in a byte. For example if there are 4 groups (i.e. bit_count is 2), there would be
    # 4 bit groups in a single byte
    int_per_byte = int(ceil(8 / bit_count))

    # Group the message (that has been converted to integers in a previous step) into
    # groups of int_per_byte integers
    grouped = [integers[i:i+int_per_byte] for i in range(0, len(integers), int_per_byte)]

    # Each group encodes a single byte in the decoded message. Map them
    as_byte_integers = [get_byte(g, bit_count, groups) for g in grouped]

    # as_byte_integers is an integer array, each value denoting a single byte, which can be converted to a bytes object
    ret = bytes(as_byte_integers)

    return ret

def encode_xor(message: bytes, key: int) -> bytes:
    """
    Encodes a message using an XOR key.

    :param message: The message to be encoded.
    :param key: The key to be XOR'd with the message.
    :returns: The encoded message.
    """

    # Convert the key into bytes so that it can be used to XOR bytes objects
    key_byte_count = int(ceil(log2(key) / 8))
    key_as_bytes = int.to_bytes(key, key_byte_count, byteorder='big')

    # Repeat the bytes of the key. For example if key is 0xABCD, this creates an infinite integer iterator
    # 0xAB 0xCD 0xAB 0xCD 0xAB 0xCD 0xAB ...
    encoder = cycle(key_as_bytes)

    # XOR each byte in the message corresponding with the key
    # If the message is 0xE00AB57AAFDC and key is 0x7A
    # The XOR pairs will look like this:
    # E0 0A B5 7A AF DC
    # 7A 7A 7A 7A 7A 7A
    ret = bytes(a ^ b for a,b in zip(message, encoder))

    return ret

def decode_xor(message: bytes, key: int) -> bytes:
    """
    Decodes a message encoded using an XOR key. This function just calls the encoding function since XOR is symmetric.
    
    :param message: The message to be decoded.
    :param key: The key to be used
    :returns: The decoded message.
    """

    return encode_xor(message, key)

def encode(message: bytes, key: int, bit_count: int, groups: list[list[int]]) -> bytes:
    """
    Encodes a message.

    :param message: The message to be encoded.
    :param key: The key to be used in XOR encoding.
    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to encode the message.
    :returns: The encoded message.
    """
    # return encode_xor(message, key)
    return encode_bit_pairs(encode_xor(message, key), bit_count, groups)

def decode(message: bytes, key: int, bit_count: int, groups: list[list[int]]) -> bytes: 
    """
    Decodes a message.

    :param message: The message to be decoded.
    :param key: The key to be used in decoding the XOR encoding.
    :param bit_count: The number of bits the groups can represent. This is here as a pre-calculation, the same value \
    can be calculated from the groups.
    :param groups: The group partitions to be used to encode the message.
    :returns: The decoded message.
    """
    # return decode_xor(message, key)
    return decode_xor(decode_bit_pairs(message, bit_count, groups), key)

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        self.precision: float = 0
        self.data: bytes = b''
        self.finished: bool = False
        self.groups: list[list[int]] = []
        self.bit_count = 0
    @staticmethod
    def is_divisable_any(n: int, me: int, divisors: list[int]) -> bool:
        """
        Calculates whether a number is divisable by any of the divisors in an array, except the number me.

        :param n: The number to be checked.
        :param me: The divisor that will not be checked.
        :param divisors: The list of divisors to be checked.
        """

        for num in divisors:
            if num == me:
                continue
            if n % num == 0:
                return False
        return True
    def calculate_groups(self, divisors: list[int]):
        """
        Pre-calculates the groups from the given divisors.

        :param divisors: The list of divisors to be used to partition the 8-bit space.
        """

        # Pre-calculate every prime in the 8-bit space
        primes = [n for n in range(2, 256) if is_prime(n)]
        self.groups = [
            [n
                for n in range(2, 256) # The 8-bit space except 0 and 1. A number belongs to a group if:
                if n % num == 0 # it is divided by the corresponding divisor
                and not is_prime(n) # it is not a prime (they are handled with the primes)
                and self.is_divisable_any(n, num, divisors) # it is not divisable by any number in the divisors, except the corresponding divisor
            ]
            for num in divisors # One group per divisor in divisors
        ]

        # Primes also create a group by themselves
        self.groups = [primes] + self.groups

        # Get all values that can be encoded with the divisors and primes
        encoded_values = set([n for g in self.groups for n in g])

        # Get all values in the 8-bit space
        all_values = set(range(256))

        # Get the unhandled values
        missing_values = list(all_values - encoded_values)

        # Unhandled values also create a group. This makes it so that there will be no value remaining in the space
        self.groups.append(missing_values)

        # The bit count is the floor of the logarithm of the number of groups. Each group correspond to
        # one value in an n-bit space. This makes it so that 2**n = group count.
        self.bit_count = int(log2(len(self.groups)))
    def send(self, log_file_name, ntp_epoch, key, time_file, divisors, port):
        """
        Sends a random message to the receiver, XOR encoded with key and group-encoded (I don't know the term) with divisors.

        :param log_file_name: The file that will be used to save the sent data. Used for comparison between sender and receiver.
        :param ntp_epoch: The difference between UNIX epoch and NTP epoch. The value is exactly 2208988800, please do not change.
        :param key: The key to be used in XOR encoding of the data. The value can be an arbitrary integer. \
        Must be the same in both sender and receiver.
        :param time_file: The file that will be used to save the throughtput values. Must be the same in both sender and receiver. \
        It will be used by the sender to save the send start time.
        :param divisors: Used to encode data, divide the 8-bit space (with 256 values). \
        The given values are used as the divisors of the groups. \
        All the values in this list must be relative primes, otherwise a group becomes empty, which breaks the program. \
        Due to the limited space of 8-bits, only 6 values (2, 3, 5, 7, 11, 13) can be given, since the other primes do not have \
        any multiple smaller than 256. There will be two other groups: the primes and all the remaining values. This makes a maximum of \
        8 groups, which means 3-bit per byte in a packet. Must be the same in both sender and receiver.
        """

        # In the first run, pre-calculate the groups and bit count so that lookup is fast
        if len(self.groups) == 0:
            self.calculate_groups(divisors)

        # Get a binary message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Save the start of the send.
        with open(time_file, 'w') as f:
            f.write(str(datetime.now().timestamp()) + '\n')

        # Convert the message to bytes instead of bits and encode it
        byte_message = bytes(int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big'))
        byte_message = encode(byte_message, key, self.bit_count, self.groups)
        
        # Pad the value with trailing zeroes
        extra_bytes_number = len(byte_message) % 4;
        padding_size = (4 - extra_bytes_number) % 4;
        byte_message = byte_message + (b'\x00' * padding_size)

        # Send the message
        for i in range(0, len(byte_message), 4):
            number = int.from_bytes(byte_message[i:i+4], byteorder='big')
            send_integer(number, super().send, ntp_epoch, port)
    
    def process_packet(self, received_packet: Packet, log_file_name: str, key: int, time_file: str, terminator: str):
            """
            Processes a packet.

            :param received_packet: The packet to be processed.
            :param log_file_name: The file that will be used to save the sent data. Used for comparison between sender and receiver.
            :param key: The key to be used in XOR encoding of the data. The value can be an arbitrary integer. \
            Must be the same in both sender and receiver.
            :param time_file: The file that will be used to save the throughtput values. Must be the same in both sender and receiver \
            It will be used by the sender to save the send start time.
            :param terminator: The last character of the stream. Currently, it must be a dot ".".
            """
            if UDP in received_packet and received_packet[UDP].dport == 123 and received_packet[IP].src != "172.18.0.3":
                # Get the secret data
                ref_timestamp_bytes = get_field_bytes(received_packet[NTPHeader], "orig")
                rightmost_bytes = ref_timestamp_bytes[-4:]
                written = rightmost_bytes

                # Append the data to the total message
                self.data = self.data + written

                # Decode the current message
                decoded = decode(self.data, key, self.bit_count, self.groups)

                # Stop receiving and save the message to the log_file_name if terminator is in the message
                if ord(terminator) in decoded[-4:]:
                    start_stamp = 0.0
                    # Get the current time as the stop time
                    stop_stamp = datetime.now().timestamp()

                    # Read the send start time from the file. It must be written by the send method before
                    with open(time_file, 'r') as f:
                        start_stamp = float(f.read())
                    
                    # Calculate the throughtput and write it to the time_file
                    with open(time_file, 'w') as f:
                        throughput = (len(decoded)) / (stop_stamp - start_stamp)
                        f.write(str(throughput) + '\n' + str(len(decoded)))
                    
                    # Write the message to the log file
                    with open(log_file_name, 'wb') as f:
                        f.write(bytes(takewhile(lambda x: x != ord(terminator), decoded)))
                        f.write(str.encode(terminator))
                    
                    # Flag the finish so that the stop_filter of sniff stops sniffing
                    self.finished = True
                # ntp_response = b'\x1c' + (  # LI=0, Version=4, Mode=4 (Server)
                #         b'\x0E'  # Stratum 2 (secondary server)
                #         b'\x06'  # Poll interval
                #         b'\xFA'  # Precision
                #         b'\x00\x00\x00\x00'  # Root Delay
                #         b'\x00\x00\x00\x00'  # Root Dispersion
                #         b'LOCL'  # Reference Identifier (e.g., Local clock)
                #         + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Reference Timestamp
                #         + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Originate Timestamp
                #         + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Receive Timestamp
                #         + get_ntp_timestamp(ntp_epoch).to_bytes(8, 'big')  # Transmit Timestamp
                # )

                # response_packet = (
                #         IP(dst="sender", src="receiver") /
                #         UDP(sport=123, dport=client_port) /
                #         Raw(load=ntp_response)
                # )

                # to make it look realistic
                # send(response_packet, verbose=0)

    def receive(self, log_file_name, key, terminator, time_file, divisors, port):
        """
        Receives an XOR- and group-encoded message from the sender and decodes it.

        :param log_file_name: The file that will be used to save the sent data. Used for comparison between sender and receiver.
        :param key: The key to be used in XOR encoding of the data. The value can be an arbitrary integer. \
        Must be the same in both sender and receiver.
        :param terminator: The last character of the stream. Currently, it must be a dot ".".
        :param time_file: The file that will be used to save the throughtput values. Must be the same in both sender and receiver \
        It will be used by the sender to save the send start time.
        :param divisors: Used to encode data, divide the 8-bit space (with 256 values). \
        The given values are used as the divisors of the groups. \
        All the values in this list must be relative primes, otherwise a group becomes empty, which breaks the program. \
        Due to the limited space of 8-bits, only 6 values (2, 3, 5, 7, 11, 13) can be given, since the other primes do not have \
        any multiple smaller than 256. There will be two other groups: the primes and all the remaining values. This makes a maximum of \
        8 groups, which means 3-bit per byte in a packet. Must be the same in both sender and receiver.
        :param port: The port to be used for connection.
        """

        # In the first run, pre-calculate the groups and bit count so that lookup is fast
        if len(self.groups) == 0:
            self.calculate_groups(divisors)
           
        # Sniff any incoming packet from port 123. Process using the process_packet method.
        sniff(
            filter=f"udp port {port}",
            prn=lambda p: self.process_packet(p, log_file_name, key, time_file, terminator),
            store=False,
            stop_filter=lambda _: self.finished
        )

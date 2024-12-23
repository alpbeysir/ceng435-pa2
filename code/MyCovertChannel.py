import scapy.utils
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPHeader

from CovertChannelBase import CovertChannelBase
from scapy.all import *

def get_field_bytes(pkt, name):
    fld, val = pkt.getfield_and_val(name)
    return fld.addfield(pkt, b"", val)

def get_ntp_timestamp(hidden_data: int = 0) -> int:
    ntp_epoch = 2208988800
    unix_time = time.time()
    ntp_time = unix_time + ntp_epoch
    seconds = int(ntp_time)

    timestamp = (seconds << 32) | hidden_data
    return timestamp

def send_integer(integer: int, sender_func):
    print(integer)
    # TODO encode integer
    current_ntp_timestamp = get_ntp_timestamp(integer)
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

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        self.precision = 0
        pass
    def send(self, log_file_name):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        # TODO encode message

        power_of_32_part = len(binary_message) // 32

        for pos in range(power_of_32_part):
            offset = pos * 32
            number = int(binary_message[offset:offset + 32], 2)
            send_integer(number, super().send)

        remaining_part_complete: str = ''
        for pos in range(power_of_32_part * 32, len(binary_message)):
            remaining_part_complete += binary_message[pos]
        if remaining_part_complete != '':
            remaining_part_complete = remaining_part_complete.rjust(32, '0')
            number = int(remaining_part_complete, 2)
            send_integer(number, super().send)

    def receive(self, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        def process_packet(received_packet: Packet):
            if UDP in received_packet and received_packet[UDP].dport == 123 and received_packet[IP].src != "172.18.0.3":
                #received_packet.show()

                client_port = received_packet[UDP].sport

                ref_timestamp_bytes = get_field_bytes(received_packet[NTPHeader], "orig")
                rightmost_bytes = ref_timestamp_bytes[-4:]
                hidden_data = int.from_bytes(rightmost_bytes, byteorder='big')
                # TODO decode hidden_data

                ntp_response = b'\x1c' + (  # LI=0, Version=4, Mode=4 (Server)
                        b'\x0E'  # Stratum 2 (secondary server)
                        b'\x06'  # Poll interval
                        b'\xFA'  # Precision
                        b'\x00\x00\x00\x00'  # Root Delay
                        b'\x00\x00\x00\x00'  # Root Dispersion
                        b'LOCL'  # Reference Identifier (e.g., Local clock)
                        + get_ntp_timestamp().to_bytes(8, 'big')  # Reference Timestamp
                        + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Originate Timestamp
                        + get_ntp_timestamp().to_bytes(8, 'big')  # Receive Timestamp
                        + get_ntp_timestamp().to_bytes(8, 'big')  # Transmit Timestamp
                )

                response_packet = (
                        IP(dst="sender", src="receiver") /
                        UDP(sport=123, dport=client_port) /
                        Raw(load=ntp_response)
                )

                # to make it look realistic
                send(response_packet, verbose=0)

        sniff(filter="udp port 123", prn=process_packet, store=False)
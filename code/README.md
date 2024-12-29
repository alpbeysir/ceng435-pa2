# CSC-PSV-NTP-TT

## Description

We implemented a covert communication channel by manipulating the reference timestamp field in the Network Time Protocol (NTP).
By lowering the precision of the timestamp, the last 4 bytes of the reference timestamp become unused, allowing them to carry hidden data.

The data is first encoded using prime number groupings, which organizes it into structured groups.
Afterwards, the grouped data is XOR-ed with a shared key known to both the sender and receiver, adding an additional layer of security.
The two-layer encoding lowers the throughput but also makes the pattern harder to detect.
We measured the throughput by writing sender/receiver timestamps to a common file.

**Measured Throughput (bits/second):**  38.35 bps

## Parameters

The implementation is configurable using the included `config.json`, which has the following parameters:

### common

- `ntp_epoch`: The beginning of time, this should be set to the standard NTP epoch value. 
- `key`: The secret shared key used by the XOR encoding code. Should be the same in both functions.
- `divisors`: Used to divide a one byte space into groups by divisibility. The groups are used to encode the message characters.

### sender

- `time_file`: This is used for performance calculation. The sender will write the time of communication start to this file.
- `log_file_name`: The file name to log the sent message to, for comparison & verification.
- `port`: The port of the sent packet. Preferably set to 123, adhering to the NTP standard.
- `target_ip`: The destination IP of the sent packet. Must point to the receiver container.

### receiver

- `time_file`: This is used for performance calculation. The receiver will write the time of communication end, the data length and measured throughput to this file.
- `log_file_name`: The file name to log the received message to, for comparison & verification.
- `port`: The ports of the sniffed packets. Preferably set to 123, adhering to the NTP standard.
- `terminator`: The receiver will stop sniffing when this character is received. Must be set to `'.'` per the homework specification.

## Misc

- Each function and its role in the project is documented using Sphinx. View the included html docs for more info.

- The system is implemented using Docker to simulate both the sender and receiver in isolated environments.
  This approach ensures a controlled and consistent setup for testing the covert channel.
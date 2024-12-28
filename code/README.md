# CSC-PSV-NTP-TT

This project implements a covert communication channel by manipulating the reference timestamp field in the Network Time Protocol (NTP).
By lowering the precision of the timestamp, the last 4 bytes of the reference timestamp become unused, allowing them to carry hidden data.

The data is first encoded using prime number groupings, which organizes it into structured groups.
Afterwards, the grouped data is XOR-ed with a shared key known to both the sender and receiver, adding an additional layer of security.
The two-layer encoding lowers the throughput a bit but also makes the pattern harder to detect.
We measured the throughput by writing sender/receiver timestamps to a common file.

**Measured Throughput (bits/second):**  14.1569

Each function and its role in the project is documented using Sphinx. View the included html docs for more info.

The system is implemented using Docker to simulate both the sender and receiver in isolated environments.
This approach ensures a controlled and consistent setup for testing the covert channel.
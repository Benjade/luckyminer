# Luckyminer

## Multi-Threaded Sha256 LuckyMiner in C++ with Real-Time Status Display

### Description
This C++ script implements a multi-threaded Sha256 LuckyMiner that connects to a mining pool via the Stratum protocol. It automatically detects the number of available CPU cores (or uses a user-specified value) to spawn multiple mining threads. The miner logs startup messages (such as pool connection, subscription, and authorization details) at the top of the terminal and then continuously displays real-time mining statistics for each thread showing hashrate, best difficulty, and nonce on separate lines below the startup information. Additionally, it listens for new job notifications from the pool and submits found blocks using the provided payout address or worker name.

LuckyMiner is designed to run on any Linux server or Windows Subsystem for Linux (WSL) and is compatible with all SHA256-based blockchains.

### Installation
On Debian/Ubuntu-based systems, install the required dependencies with:

```bash
sudo apt update
sudo apt install g++ libssl-dev nlohmann-json3-dev
```
# Compilation
Compile the script using:

```bash
g++ miner.cpp -o miner -lssl -lcrypto -std=c++11 -pthread
```
# Usage
Run the miner with the following syntax:
```bash
./miner [pool_address] [pool_port] [payout_address] [num_mining_threads]
```
For example, to mine Nito on pool eu.minto.day at port 3333 with a specific payout address using 3 mining threads:
```bash
./miner eu.minto.day 3333 nito1q8wvdpfk78l85gnmdxsvpjguwvh02kw7lqcgxva 3
```
Or, to mine on pool solo.ckpool.org at port 3333 with a specific payout address using 6 mining threads:
```bash
./miner solo.ckpool.org 3333 1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o 6
```
If no arguments are provided, the script defaults to test:

Pool: solo.ckpool.org:3333

Payout address: 1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o

Number of mining threads: Automatically detected from your CPU cores.

# License and Donation Notice
Feel free to redistribute, modify, and share this script as you wish. This script is provided "as is" without any warranty. LuckyMiner is designed for educational purposes.

# Donations are welcome and greatly appreciated; please send them to the following address:

1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o

Note: LuckyMiner is fully compatible with any Linux server or Windows Subsystem for Linux (WSL) and works with all SHA256-based blockchains.

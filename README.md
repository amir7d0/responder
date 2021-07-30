# responder
A Python-based DNS, ICMP, and ARP responder

The full version of Headers.py was written in [packet-analyzer](https://github.com/amir7d0/packet-analyzer).
### Features

- Capturing DNS, ICMP, and ARP packets and save them in pcap file and print them onto cli
- Parses DNS, ICMP, and ARP packets and sends response to packet sender
- Supports the following protocols :
	- ARP
	- ICMP
	- DNS

## Requirement
- Python 3.x
	- socket
	- struct
	- textwrap
	- time
	- binascii
- Linux Operatin System
- Administrator Privileges "super user do"


## Run

```sh
sudo python3 app.py
```

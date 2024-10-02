
# Packet Interceptor with Injection

This script is a basic packet interceptor using `NetfilterQueue` and `Scapy`. It intercepts packets, processes them, and injects code into HTTP responses before forwarding them to their original destination.

## Prerequisites

- Python 3.x
- Scapy library
- NetfilterQueue library

You can install the necessary dependencies by running:

```
pip install scapy netfilterqueue
```

Additionally, you need to set up `iptables` rules to redirect the network traffic to the `NetfilterQueue`. You can do this with the following commands:

```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

## How It Works

- The script binds to a specified NetfilterQueue and processes packets.
- For HTTP requests (packets with destination port 80), it removes the `Accept-Encoding` header to prevent content compression.
- For HTTP responses (packets with source port 80), it injects a script tag containing an alert message (`<script>alert('test')</script>`) before the `</head>` tag of the HTML content.
- The script adjusts the `Content-Length` header to account for the size of the injected code.

## Code Breakdown

- `set_load(packet, load)`: Updates the payload of the packet and recalculates the IP and TCP checksum.
- `process_packet(packet)`: Processes each packet by checking whether it's an HTTP request or response. In the case of an HTTP response, it injects JavaScript into the HTML content.
- `queue.bind(0, process_packet)`: Binds the packet processing function to queue number 0.

## Usage

1. Set up the necessary `iptables` rule:
```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

2. Run the script with root privileges:
```
sudo python3 packet_interceptor.py
```

3. After running, the script will intercept HTTP traffic and inject JavaScript alerts into responses.

## Example

When the script intercepts an HTTP response, it injects a JavaScript alert like the following:

```
<script>alert('test')</script>
```

The modified HTML response will trigger this alert when loaded in the browser.

## Disclaimer

0x1tsjusthicham
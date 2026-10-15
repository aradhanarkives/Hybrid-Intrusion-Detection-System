from scapy.all import sniff, IP, TCP, UDP


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"

    source_port = 0
    destination_port = 0

    if TCP in packet:

        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    print(
        f"{source_ip} → "
        f"{destination_ip} | "
        f"{protocol} | "
        f"{source_port} → {destination_port}"
    )


def start_monitoring(interface=None):

    sniff(
        iface=interface,
        prn=process_packet,
        store=False
    )
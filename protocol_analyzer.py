def analyze_packet(packet):
    if not packet.haslayer('Ether'):
        return None

    result = {
        "src_mac": packet['Ether'].src,
        "dst_mac": packet['Ether'].dst,
        "proto_name": "Unknown"
    }

    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        result.update({
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ip_proto": ip_layer.proto,
        })

        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            result.update({
                "protocol": "TCP",
                "sport": tcp_layer.sport,
                "dport": tcp_layer.dport
            })
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            result.update({
                "protocol": "UDP",
                "sport": udp_layer.sport,
                "dport": udp_layer.dport
            })
        elif packet.haslayer('ICMP'):
            result["protocol"] = "ICMP"
    else:
        result["protocol"] = "Non-IP"

    return result
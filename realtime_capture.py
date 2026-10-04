from scapy.all import sniff, DNS, DNSQR, IP
from collections import defaultdict
import requests
from feature_extraction import calculate_entropy, get_query_length, get_base_domain, get_subdomain_label

MY_IP = "192.168.1.9"  # only track queries from your own machine

# tracker[(source_ip, base_domain)] = {"count": int, "subdomains": set()}
tracker = defaultdict(lambda: {"count": 0, "subdomains": set()})

def handle_packet(packet):
    try:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip != MY_IP:
                return  # skip router/duplicate noise

            query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')

            base_domain = get_base_domain(query_name)
            subdomain_label = get_subdomain_label(query_name)

            key = (src_ip, base_domain)
            tracker[key]["count"] += 1
            tracker[key]["subdomains"].add(subdomain_label)

            entropy = calculate_entropy(query_name)
            query_length = get_query_length(query_name)
            query_frequency = tracker[key]["count"]
            unique_subdomain = len(tracker[key]["subdomains"])

            payload = {
                "entropy": entropy,
                "query_length": query_length,
                "query_frequency": query_frequency,
                "unique_subdomain": unique_subdomain,
                "source_ip": src_ip,
                "domain": query_name,
                "query_type": "A"
            }

            response = requests.post("http://127.0.0.1:5000/score", json=payload)
            result = response.json()
            print(f"{src_ip} -> {query_name} | score={result['score']} severity={result['severity']}")

    except Exception as e:
        print(f"Skipped a packet due to: {e}")

print("Listening for DNS queries... (Ctrl+C to stop)")
sniff(filter="udp port 53", prn=handle_packet, store=False)
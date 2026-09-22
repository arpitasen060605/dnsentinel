import random
import string
import csv
from datetime import datetime, timedelta 

tunnel_base_domains= ["evil-tunnel.com", "c2server.net", "datax-relay.io"]

normal_domains = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "yahoo.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com"
]

subdomains = ["www", "mail", "api", "cdn", "static", ""]

infected_ips = ["192.168.1.50", "192.168.1.51"]

def infected_ip():
    return random.choice(infected_ips)

def random_encoded_string(length):
    charset= string.ascii_lowercase + string.digits
    return ''.join(random.choice(charset) for _ in range(length))

def generate_tunnel_query():
    domain= random.choice(tunnel_base_domains)
    encoded_length= random.randint(20,50)
    sub= random_encoded_string(encoded_length)
    full_domain= f"{sub}.{domain}"
    return full_domain

def generate_normal_query():
    domain = random.choice(normal_domains)
    sub = random.choice(subdomains)
    full_domain = f"{sub}.{domain}" if sub else domain
    return full_domain

def random_ip():
    return f"192.168.1.{random.randint(2, 254)}"

def generate_dataset(num_normal=200, num_tunnel=50, filename="dns_dataset.csv"):
    rows= []
    base_time = datetime(2026, 9, 11, 10, 0, 0)

    for i in range(num_normal):
        rows.append({
            "timestamp": (base_time + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip":random_ip(),
            "domain": generate_normal_query(),
            "query_type": "A",
            "label": "normal"
        })
    for i in range(num_tunnel):
        rows.append({
            "timestamp": (base_time + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": infected_ip(),
            "domain":generate_tunnel_query(),
            "query_type": random.choice(["TXT", "A", "NULL"]),
            "label": "tunneling"
        })
    random.shuffle(rows)

    with open(filename, "w", newline="") as f:
        writer= csv.DictWriter(f, fieldnames=["timestamp", "source_ip", "domain", "query_type", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generate {len(rows)} rows into {filename}")
generate_dataset()  


import pandas as pd
import requests
from feature_extraction import calculate_entropy, get_query_length, get_base_domain, get_subdomain_label

df = pd.read_csv("pcap_queries.csv")
df["dns.qry.name"] = df["dns.qry.name"].astype(str)

df["base_domain"] = df["dns.qry.name"].apply(get_base_domain)
df["subdomain_label"] = df["dns.qry.name"].apply(get_subdomain_label)

df["entropy"] = df["dns.qry.name"].apply(calculate_entropy)
df["query_length"] = df["dns.qry.name"].apply(get_query_length)

grouped = df.groupby(["ip.dst", "base_domain"]).agg(
    avg_entropy=("entropy", "mean"),
    avg_query_length=("query_length", "mean"),
    query_frequency=("dns.qry.name", "count"),
    unique_subdomain=("subdomain_label", "nunique")
).reset_index()

print(grouped)
print()


for _, row in grouped.iterrows():
    payload = {
        "entropy": row["avg_entropy"],
        "query_length": row["avg_query_length"],
        "query_frequency": row["query_frequency"],
        "unique_subdomain": row["unique_subdomain"],
        "source_ip": row["ip.dst"],
        "domain": row["base_domain"],
        "query_type": "TXT"
    }
    response = requests.post("http://127.0.0.1:5000/score", json=payload)
    result = response.json()
    print(f"{row['ip.dst']} -> {row['base_domain']}: {result}")
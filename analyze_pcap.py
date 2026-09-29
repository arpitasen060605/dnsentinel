import pandas as pd
from feature_extraction import calculate_entropy

df = pd.read_csv("pcap_queries.csv")

df["label"] = df["ip.dst"].apply(lambda ip: "tunnel" if ip == "127.0.0.1" else "baseline")
df["entropy"] = df["dns.qry.name"].apply(lambda x: calculate_entropy(str(x)))

print(df[["dns.qry.name", "label", "entropy"]])
print("\n=== Average entropy by label ===")
print(df.groupby("label")["entropy"].mean())
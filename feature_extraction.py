import math
from collections import Counter
import pandas as pd

def calculate_entropy(text):
    if len(text) == 0:
        return 0
    counts= Counter(text)
    entropy_sum = 0
    for char in counts:
        probability = counts[char] / len(text)
        entropy_sum += probability * math.log2(probability)
    return -entropy_sum 

def get_query_length(domain):
    return len(domain)

def get_subdomain_length(domain):
    dot_index = domain.find(".")
    if dot_index == -1:
        return len(domain)
    return dot_index

def get_base_domain(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:])     

def calculate_query_frequency(df):
    df["base_domain"]= df["domain"].apply(get_base_domain)
    freq = df.groupby(["source_ip", "base_domain"]).size().reset_index(name="query_count")
    return freq

def get_subdomain_label(domain):
    base = get_base_domain(domain)  
    subdomain = domain[:-(len(base) + 1)]  
    return subdomain

def calculate_unique_subdomains(df):
    df["base_domain"] = df["domain"].apply(get_base_domain)
    df["subdomain_label"] = df["domain"].apply(get_subdomain_label)
    
    unique_counts = df.groupby(["source_ip", "base_domain"])["subdomain_label"].nunique().reset_index(name="unique_subdomain_count")
    return unique_counts

if __name__ == "__main__":
    df = pd.read_csv("dns_dataset.csv")
    freq = calculate_query_frequency(df)
    print("=== Query Frequency ===")
    print(freq.sort_values("query_count", ascending=False).head(10))   

    unique = calculate_unique_subdomains(df)
    print("\n=== Unique Subdomains ===")
    print(unique.sort_values("unique_subdomain_count", ascending=False).head(10))           
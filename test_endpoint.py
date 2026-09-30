import requests 
response = requests.post(
    "http://127.0.0.1:5000/score",
    json={
        "entropy": 3.6,
        "query_length": 28,
        "query_frequency": 12,
        "unique_subdomain": 10,
        "source_ip": "192.168.1.50",
        "domain": "x8f2a91.evil-tunnel.com",
        "query_type": "TXT"
    }
)
print(response.json())
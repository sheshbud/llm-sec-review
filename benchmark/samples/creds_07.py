import requests
API_KEY = "sk-live-9f3a2b7c4d1e8a6f0b5c3d9e2a7f4b1c"
def push(payload):
    return requests.post("https://api.example.com/v1/ingest",
                         headers={"Authorization": "Bearer " + API_KEY}, json=payload)

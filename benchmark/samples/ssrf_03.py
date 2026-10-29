import requests
def fetch_preview(url):
    return requests.get(url, timeout=5).text

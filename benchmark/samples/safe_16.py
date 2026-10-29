import subprocess
def ping(host):
    if not host.replace(".", "").isalnum():
        raise ValueError("bad host")
    subprocess.run(["ping", "-c", "1", host], check=False)

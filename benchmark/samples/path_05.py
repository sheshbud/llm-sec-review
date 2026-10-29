import os
BASE = "/var/data"
def read_report(name):
    with open(os.path.join(BASE, name)) as f:
        return f.read()

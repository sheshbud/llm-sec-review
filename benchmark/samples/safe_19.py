import os
BASE = "/var/data"
def read_report(name):
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        raise ValueError("path escape")
    with open(path) as f:
        return f.read()

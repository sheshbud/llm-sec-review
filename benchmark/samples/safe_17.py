import hashlib, os
def store_password(pw):
    salt = os.urandom(16)
    return salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000).hex()

"""Static-analysis fixture: weak cryptographic choices."""
import hashlib
import random

def create_token(user_id):
    # MD5 and the non-cryptographic PRNG are intentionally weak examples.
    digest = hashlib.md5(str(user_id).encode()).hexdigest()
    return f"{digest}-{random.randint(1000, 9999)}"

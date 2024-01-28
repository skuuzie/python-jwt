from jwt import JWT, JWTError, Util

jwt = JWT()

try:
    jwt.sign(b'KEYYYYYY', "{1:'must be a dictionary'}", algorithm='HS512')
except (JWTError) as e:
    print(e)

try:
    jwt.sign(b'ecc_key', {1:2}, algorithm='ES512')
except (ValueError) as e:
    print(e)

try:
    jwt.sign(b'rsa_key', {1:2}, algorithm='RS512')
except (ValueError) as e:
    print(e)

try:
    ecc_key = """-----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMykrnDZfbgJdOT6z
                vqXUm8hSFqvtvJYxeKn5CmH4FrChRANCAARjk5jrGAdUHCP3dGRU9bvYlYCAUhmq
                VDUGhiZ0Ha7qFGVn4a5AaTARHDfFfqhhoxUnzkxfUN65s7XivIwIDsHh
                -----END PRIVATE KEY-----"""
    jwt.sign(ecc_key, {1:2}, algorithm='ES512')
except (JWTError) as e:
    print(e)

try:
    jwt.sign(b'sha', {1:2}, algorithm='MD5')
except (JWTError) as e:
    print(e)

try:
    Util.generate_ecc_key(1024)
except (JWTError) as e:
    print(e)

try:
    Util.generate_rsa_key(512)
except (JWTError) as e:
    print(e)

try:
    Util.get_sha(500)
except (JWTError) as e:
    print(e)
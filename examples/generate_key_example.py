from jwt import Util

# will save the key pairs in the same folder
Util.generate_ecc_key(512, save_key=True)
Util.generate_rsa_key(2048, save_key=True)
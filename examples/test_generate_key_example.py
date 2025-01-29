from jwt import Util

import os.path

# will save the key pairs in the same folder
Util.generate_ecc_key(512, save_key=True)
Util.generate_rsa_key(2048, save_key=True)

def test_generated_keys_existence():
    assert os.path.isfile('ecc_public_key.pem') == True
    assert os.path.isfile('ecc_private_key.pem') == True

    assert os.path.isfile('rsa_public_key.pem') == True
    assert os.path.isfile('rsa_private_key.pem') == True
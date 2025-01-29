from jwt import JWT
from time import time
from json import dumps

jwt = JWT()

current_epoch = int(time())

ecc_key = """-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBr+kbyD/KRWAGbKd0
NcX+j3wGYgUqhlyO4IW6fi1KeyVoLwLkV7BXUynITMPp3qHeJAksz9VKliIjAEah
dfdEVQKhgYkDgYYABAGaV2TJlx8DQfy2iDBjT3m+rr3dZmAfAV3mNoXnMylMOyGn
7nXpsJ81ou8MFl1afc+iNep6c8EfLHN0oY6Pi/wNPAG3uoRo/0D38ONqzX8h0t+r
M62YNF6zBeVxQA165Y49ALVxaNi6PCwHDVGXsDhnUHdcWyCUwt9DQF0+F30y9G1Q
rA==
-----END PRIVATE KEY-----"""

ecc_public_key = """-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBmldkyZcfA0H8togwY095vq693WZg
HwFd5jaF5zMpTDshp+516bCfNaLvDBZdWn3PojXqenPBHyxzdKGOj4v8DTwBt7qE
aP9A9/Djas1/IdLfqzOtmDReswXlcUANeuWOPQC1cWjYujwsBw1Rl7A4Z1B3XFsg
lMLfQ0BdPhd9MvRtUKw=
-----END PUBLIC KEY-----"""

incorrect_ecc_public_key = """-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBXwnuQI3cMDyZQn9V3+q2jFlK6OVy
Erx0LA9UbW1de9XaE49pNf2JnRzv7NRn+iro/CSKq4dBXlLcU7ffiDQbdi0B4oCX
nsKzkJPwi0/+mT0I1RBeBhQJRK2yEZR2SGce83UfWspWC9oPIg1KW48KmP+mnF3E
zPWkaJ6JseZuVhqSmsE=
-----END PUBLIC KEY-----"""

payload = {
    'iss': 'asd',
    'iat': current_epoch,
    'exp': current_epoch + 3600,
    'user_id': '123123123123'
}

generated_jwt = jwt.sign(ecc_key, payload, 'ES512')

valid = jwt.validate(ecc_public_key, generated_jwt)
invalid = jwt.validate(incorrect_ecc_public_key, generated_jwt)

print(dumps(payload, indent=4), '\n')
print(generated_jwt, '\n')
print(valid, '\n')
print(invalid, '\n')

def test_keys_validity():
    assert valid == True
    assert invalid == False
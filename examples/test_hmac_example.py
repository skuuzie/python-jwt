from jwt import JWT
from time import time
from json import dumps

jwt = JWT()

current_epoch = int(time())

key = 'hmac Secret must be veryyyyyyyy longgggggggggggg'
incorrect_key = 'secret'

payload = {
    'iss': 'asd',
    'iat': current_epoch,
    'exp': current_epoch + 3600,
    'user_id': '123123123123'
}

generated_jwt = jwt.sign(key, payload, 'HS512')
valid = jwt.validate(key, generated_jwt)
invalid = jwt.validate(incorrect_key, generated_jwt)

print(dumps(payload, indent=4), '\n')
print(generated_jwt, '\n')
print(valid, '\n')
print(invalid, '\n')

def test_key_validity():
    assert valid == True
    assert invalid == False
from jwt import JWT
from time import time
from json import dumps

jwt = JWT()

current_epoch = int(time())

rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIIG4gIBAAKCAYEAnpVvl5eJgzmjiyLJJI0ulSIA1XZCFWtL3hTMi+7yJvGy/Tol
XnK2eqiXgnCEclk2Lnti2YBY2QAiE8mdvqusRSyRuD+FJoO70CYMG0gCItov+7mr
Ys0Rgol7wdvs34KyOBb5g4z+7HVU5wrncSn1ySvd2ymFkSWsU2U4yWHvb7giUwiY
N13vQZfSTL2MbstFDS4e2o1/RVwXhO6zKkMfdApVhFbEARRTZIvyfjWD5d3pFSte
7TMjCPOJGs3M/IJQmcOeR5TATeHXO2pMkiwuO+HzRdCokLbtfHYHGGSwIPURA/kh
+MuIABq+dAqr472HoAawwC6Bi9A7ce+IGREmaiVrfB+ttZPZOSnT/sLiUIiAB7XE
ZtZ6uSgg6NfVL59zhi8uM4QQW/ZhOne7R1Ixp3wHVDx8V1DgR4hIogAsavsQPQ6i
qwI39vsS7kjRWd68a7jHHDd/rzMyNKHV5T2bjgBSvhhodwUKJOvDzDcBgjGHMa6J
JWf8j/cLB0BkjfjTAgMBAAECggGASjLCISvyV7c2uWlfsl3qTzW3LSklN09aEoEp
yUlV/Hm3FPtJM705ev950DqkBbqO+sWZVQnTyEhjKV36lBVPx5fYYFw8CO63B+dd
X8Bb24G51K4lLdekGy8HfAdR96v3hf3d5bqpJeqp/GYiLtUCnosLRTlSuLxnOifQ
n4zWki+Vw8LwMWuef9Kwv14qoEY0Ozv6jKiKxWGW0Yg7xQjd5RXWuFI+aADiGdfO
8FVKrtka7uA5jIMSH+SOoD9tazHvFrAKclJj/tcyPchUdJ+E4XePj4UpapUNjvE6
j4AB76rqFFX5k0RAzhkTva24wnOBMCOCIya58ijxtswiIdOtVGoLpcHzXbG96ofj
9o5aJMmpzbn0ZvX6CTPSZdEhwEDdsvZJqoJboqrjsiCXNAHxCzaq5Qqvq4LldjVp
GeTKSkmQZlj3EXRuyQx2kiS5+mg68hg+1SyJf9/lasB8fCbLHrWtSbsv/4hKJxNd
W3FL4C6NGXSzOYH5Ua6RZHnv5VWNAoHBAMJ1b5CHOwyfBJixv5Uq8SJNioBQ+K/a
R0uRP8yAqXqr2fx7P3QXStmfMJHs9sLr7uhFQMx82ZWD7BR3RzDWyVulzLEI6HEQ
9FM2V4U5gNgnUpoIfWZK+g5GIS/2GeiS0H0orHSUP17xPG7bxrGyCnvbICeM5Iee
wfO+to1OZ4oLHBeSZuTizAyDwDjWnODyFYfXljxqkBaEsyfvNK+4X23gC2Adbgz5
IrXUe11lmasI7SCo96tbjR/yHA1qvr6p3wKBwQDQxX8jnLbujqyS+pY9MaYEm7oG
P9UmKAHn0cKaQmETsD56dxouZZGOiqqs/mAbnpW8cij4VTKfSwvWwsDvQlkD3hS8
pAZx0qo4rPtKsZYbiAGmGWzY8aYZ/hVDy5th4Hw3HU1FmMR+jL6IOXvqd8p0+nRO
sH9AgtPaGRS5BcWjQznjT39si6TCEaOk7P4GeHOxey/vh9HiWN6lH+/nE/lrYPGN
PQOvAijZ6YqBieRsh568zlgoN5289BB5gzFkt40CgcA+p4/2xVulSWc1u6+65Ecl
gk5p4az/HBl0o6wmvB3fRJfL3fon8YlQbRY9LlijnVkwxX+HY4LHxeW/Al+RwOLI
ALffIruiEpBmb0/rwQdenezjbHDbELVY/AedaHIYmZVLfltyhIGWmaubHHz8rBzs
o0HM/Hx1phVf78bp6KU7uTCn96fnf5u3PIwmxB9v6xA84J2rgbpDRyZia5RSOdml
kVaY9WKME4m3hGrrQN0uWoXszARg1fK2pE+dkxM6Y4kCgcBuDR33NN5NpNId7JCU
E37zgO+v6ag/o+lVPYK69HDeAxL8VZpsiMgQ/tH3vWQGSzOdkgQ83BSCWfoUrLct
qKjp3ADMbB6lk6p9k9onxrNdMfXEjDSPq9qmawTkpwjysHZqSzz3ig9SsnihsMO8
locX4Qq8jFeYNx7cIkqFOiCz7nUueTKvknE4iDneb7t8x7QdA9YCC3O9QKGlI8+/
3Qym6QSMMnSlpZrJPE3x+TF7cIZh+tgH40F4YKPqmhjIgeUCgcBDdaFdALBdblcC
9Ko7Z6em5OQW/xoTwzLQ+bF5Tp96+xMNAbus+o2Lmw3bhACWVtutDYs2DppbVNBE
tsIgyKWcUQSJZIpL2xVh8PgB/AMlYXP5NBj1nxezB3ipFUU6+yuTpBra5Uv77nXI
kqKW40So1cQALus/bMvDtf+QY0dyOhkDqm29iTd/ul5R6ehlrGaVyDDPUDwwhrRa
4a9OYoZXy8guheZ69ZkYY6rcCcQLhT8ClJBKi/Ybza5CDkcvZ+Y=
-----END RSA PRIVATE KEY-----"""

rsa_public_key = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnpVvl5eJgzmjiyLJJI0u
lSIA1XZCFWtL3hTMi+7yJvGy/TolXnK2eqiXgnCEclk2Lnti2YBY2QAiE8mdvqus
RSyRuD+FJoO70CYMG0gCItov+7mrYs0Rgol7wdvs34KyOBb5g4z+7HVU5wrncSn1
ySvd2ymFkSWsU2U4yWHvb7giUwiYN13vQZfSTL2MbstFDS4e2o1/RVwXhO6zKkMf
dApVhFbEARRTZIvyfjWD5d3pFSte7TMjCPOJGs3M/IJQmcOeR5TATeHXO2pMkiwu
O+HzRdCokLbtfHYHGGSwIPURA/kh+MuIABq+dAqr472HoAawwC6Bi9A7ce+IGREm
aiVrfB+ttZPZOSnT/sLiUIiAB7XEZtZ6uSgg6NfVL59zhi8uM4QQW/ZhOne7R1Ix
p3wHVDx8V1DgR4hIogAsavsQPQ6iqwI39vsS7kjRWd68a7jHHDd/rzMyNKHV5T2b
jgBSvhhodwUKJOvDzDcBgjGHMa6JJWf8j/cLB0BkjfjTAgMBAAE=
-----END PUBLIC KEY-----"""

incorrect_rsa_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWN3/aEJaY97VWW/n1G3
LVn0e5ocDjGZsyjVd4rN/X4NP1Iu+AIOB5uAyQuVlonBykczZx4O+scdKv5TyovT
x1wyQiUyrhbOJiAc1fXF8Fj0pN9HplIb9H6Xj7feauK1fHImM0cX48wJ32jMQb0b
gH6JIx1w8iuDgiNtmMgrJNt17X+Y3q+H37vs91uFgCa2mIZ5zqqp71AzAJIz1i6w
KwY/S7sczBJQPmbsbSmT3a3LxS13jG34hlfkdFeWGxwyFg+izIIcY6Ks3iCezXcc
+JfAuqEJsnnBJrKNbCkpB1E2iiotLGeNidY6FEXVsynAaheM3ZYo1QdKfGaLKf/S
LQIDAQAB
-----END PUBLIC KEY-----"""

payload = {
    'iss': 'asd',
    'iat': current_epoch,
    'exp': current_epoch + 3600,
    'user_id': '123123123123'
}

generated_jwt = jwt.sign(rsa_key, payload, 'RS512')
#generated_jwt = jwt.sign(rsa_key, payload, 'PS512')

valid = jwt.validate(rsa_public_key, generated_jwt)
invalid = jwt.validate(incorrect_rsa_public_key, generated_jwt)

print(dumps(payload, indent=4), '\n')
print(generated_jwt, '\n')
print(valid, '\n')
print(invalid, '\n')

def test_keys_validity():
    assert valid == True
    assert invalid == False
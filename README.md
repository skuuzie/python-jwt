# python-jwt

A simple single-file JWT (RFC 7519) implementation in python.

Requirements
------------

[The PyCryptodome library](https://pypi.org/project/pycryptodome/) 
```pip install pycryptodome```

Features
--------

- JWT Generation and Validation
- Supported algorithms: HMAC, RSA (PKCS & PSS), ECDSA
- Supported key sizes: 256, 384, 512
- RSA & ECC Key-pair Generation 

Usage
-----

To generate a JWT
```
sign(key, payload, algorithm)
```

To validate a JWT
```
validate(key, jwt, algorithm)
algorithm is optional for validation, but highly recommended. see rfc8725#section-3
```

To generate a key-pair
```
generate_rsa_key(size, save_key=True)
generate_ecc_key(size, save_key=True)
```

See `*_example.py` files in `examples` folder for example usage of each algorithm.

For testing, use [JWT.IO](https://jwt.io/) or check `examples` with `pytest`

Notes
-----

This module is only a personal project, use the popular ones for more up-to-date JWT features :D

References
----------

- [RFC 7518: JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 8725: JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/en/latest/index.html)

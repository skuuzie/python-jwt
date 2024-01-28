from base64 import urlsafe_b64encode, urlsafe_b64decode

from json import dumps as json_dumps
from json import loads as json_loads

from Crypto.Hash import SHA256, SHA384, SHA512, HMAC
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15, pss

from os import urandom

available_algorithms = ( # 
    'HS256', 'HS384', 'HS512', # HMAC
    'RS256', 'RS384', 'RS512', # RSASSA-PKCS1-v1_5
    'PS256', 'PS384', 'PS512', # RSASSA-PSS
    'ES256', 'ES384', 'ES512'  # ECDSA
)

class JWTError(Exception):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class JWT:

    __separator = '.'

    def __init__(self):
        self.__algorithm = None
        self.__alg = None
        self.__size = None
        self.__header = None
    
    def __set_algorithm(self, algorithm):

        if algorithm not in available_algorithms:
            raise JWTError('Invalid or unsupported algorithm')
        
        self.__algorithm = algorithm

        self.__alg = self.__algorithm[:2]
        self.__size = int(self.__algorithm[2:])
        
        self.__header = {
            "alg": self.__algorithm,
            "typ": "JWT"
        }
    
    def __load_key(self, key: str | bytes):

        h = None
        signer = None

        if self.__alg == 'HS':
            if isinstance(key, str):
                _key = key.encode()
            else:
                _key = key

            h = HMAC.new(_key, digestmod=Util.get_sha(self.__size))
        
        elif self.__alg in ('RS', 'PS', 'ES'):
            if self.__alg == 'ES':
                _key = ECC.import_key(key)
                
                if int(_key.curve[-3:]) < int(self.__size):
                    raise JWTError(f"Key type is {_key.curve}, can't do {self.__algorithm} - Use larger key")
            else:
                _key = RSA.import_key(key)

            if self.__alg == 'RS':
                signer = pkcs1_15.new(_key)
            elif self.__alg == 'PS':
                signer = pss.new(_key, rand_func=urandom)
            elif self.__alg == 'ES':
                signer = DSS.new(_key, mode='fips-186-3', randfunc=urandom)

            h = Util.get_sha(self.__size)
            
        return h, signer
    
    def sign(self, key: str | bytes, payload: dict, algorithm: str = None) -> str:
        """
        Generate a JWT

        key: receives any string or bytes as long it satisfy the target algorithm

        payload: dictionary (json), receives ANY claims. For recommendation see RFC 7519

        algorithm: see available_algorithms

        --- pycryptodome exception may arise if invalid key, etc. ---

        Return a string of encoded JWT.
        """

        if algorithm is None:
            raise JWTError(f'Specify the algorithm: {available_algorithms}')

        self.__set_algorithm(algorithm)

        h, signer = self.__load_key(key)
        
        if not isinstance(payload, dict):
            raise JWTError('Payload must be a dictionary')

        header = Util.dict_to_b64(self.__header)
        payload = Util.dict_to_b64(payload)

        h.update(header.encode())
        h.update(JWT.__separator.encode())
        h.update(payload.encode())

        if self.__alg == 'HS':
            signature = h.digest()
        elif self.__alg in ('RS', 'PS', 'ES'):
            signature = signer.sign(h)

        jwt = ''

        jwt += header
        jwt += JWT.__separator
        jwt += payload
        jwt += JWT.__separator
        jwt += Util.b64encode(signature)

        return jwt
    
    def validate(self, key: str | bytes, jwt: str, algorithm: str = None):
        """
        Validate a JWT

        key: receives any string or bytes as long it satisfy the target algorithm

        jwt: encoded JWT string

        algorithm: (optional, highly recommended) see available_algorithms

        --- pycryptodome exception may arise if invalid key, etc ---

        Return a boolean whether the JWT is valid or not.
        """

        if not self.__separator in jwt:
            return False
        
        header, payload, claimed_signature = jwt.split('.')

        if algorithm:
            if algorithm != Util.json_to_dict(header)['alg']:
                return False
            
            self.__set_algorithm(algorithm)
        else:
            self.__set_algorithm(Util.json_to_dict(header)['alg'])

        h, signer = self.__load_key(key)

        h.update(header.encode())
        h.update(JWT.__separator.encode())
        h.update(payload.encode())

        claimed_signature = Util.b64decode(claimed_signature)

        if self.__alg == 'HS':
            return h.digest() == claimed_signature
        elif self.__alg in ('RS', 'PS', 'ES'):
            try:
                signer.verify(h, claimed_signature)
                return True
            except:
                return False

class Util:

    pki_keysize = (1024, 2048, 3072)
    bit_keysize = (256, 384, 512)

    @staticmethod
    def b64decode(s: str) -> str:

        if len(s) % 4 != 0:
            s += '=='
        
        return urlsafe_b64decode(s)

    @staticmethod
    def b64encode(s: str | bytes | bytearray) -> str:

        if isinstance(s, str):
            s = s.encode()

        return urlsafe_b64encode(s).decode().rstrip('=')

    @staticmethod
    def dict_to_json(d: dict):

        if not isinstance(d, dict):
            raise JWTError('Must be dictionary')
        
        return json_dumps(d, separators=(',', ':'))

    @staticmethod
    def dict_to_b64(d: dict):

        d = Util.dict_to_json(d)

        return Util.b64encode(d)
    
    @staticmethod
    def json_to_dict(j: str):

        j = Util.b64decode(j)

        return json_loads(j)
    
    @staticmethod
    def generate_random_bytes(size: int):
        """
        any size, return in bytes
        """
        return urandom(size)
    
    @staticmethod
    def generate_rsa_key(size: int, save_key=False):
        """
        Generates random RSA key pair (private & public)

        size: 1024, 2048, 3072

        Recommended minimum size is 2048.

        returns: RsaKey | None (Public & Private key will be saved instead)
        """

        if size not in Util.pki_keysize:
            raise JWTError(f'RSA Key size must be either {Util.pki_keysize} - FIPS standards')

        rsa = RSA.generate(size, randfunc=urandom)

        if save_key:
            open('rsa_public_key.pem', 'w').write(rsa.public_key().export_key(format='PEM').decode())
            open('rsa_private_key.pem', 'w').write(rsa.export_key(format='PEM').decode())
            return
        
        return rsa
    
    @staticmethod
    def generate_ecc_key(size: int, save_key=False):
        """
        Generates random ECC key pair (private & public)

        size: 256 | 384 | 512

        Recommended size is 512 (P-521), suitable for any ECDSA Algorithm.

        returns: EccKey | None (Public & Private key will be saved instead)
        """

        if size not in Util.bit_keysize:
            raise JWTError(f'ECC Key size must be either {Util.bit_keysize} - FIPS standards')
        
        if size == 256:
            curve = 'NIST P-256'
        elif size == 384:
            curve = 'NIST P-384'
        elif size == 512:
            curve = 'NIST P-521'

        ecc = ECC.generate(curve=curve, randfunc=urandom)

        if save_key:
            open('ecc_public_key.pem', 'w').write(ecc.public_key().export_key(format='PEM'))
            open('ecc_private_key.pem', 'w').write(ecc.export_key(format='PEM'))
            return None

        return ecc
    
    @staticmethod
    def get_sha(size: int):

        if size not in Util.bit_keysize:
            raise JWTError(f'SHA digest size must be either {Util.bit_keysize}')
        
        size = str(size)
        
        if size == '256':
            return SHA256.new()
        elif size == '384':
            return SHA384.new()
        elif size == '512':
            return SHA512.new()
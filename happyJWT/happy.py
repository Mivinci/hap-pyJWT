from typing import Tuple, Dict
from hashlib import md5, sha512, sha224, sha256, sha384, sha1
from datetime import datetime
import base64
import time

HS1 = 'HS1'
HS224 = 'HS224'
HS256 = 'HS256'
HS384 = 'HS384'
HS512 = 'HS512'
MD5 = 'md5'

class Hash:
    _hash = None

    @classmethod
    def sha1(cls, s: str, salt: str):
        cls._hash = sha1(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def sha224(cls, s: str, salt: str):
        cls._hash = sha224(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def sha256(cls, s: str, salt: str):
        cls._hash = sha256(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def sha384(cls, s: str, salt: str):
        cls._hash = sha384(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def sha512(cls, s: str, salt: str):
        cls._hash = sha512(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def md5(cls, s: str, salt: str):
        cls._hash = md5(salt.encode('utf-8'))
        return cls.digest(s)

    @classmethod
    def digest(cls, s):
        cls._hash.update(s.encode('utf-8'))
        return cls._hash.hexdigest()


mapping: Dict[str, callable] = {
    HS1: Hash.sha1,
    HS224: Hash.sha224,
    HS256: Hash.sha256,
    HS384: Hash.sha384,
    HS512: Hash.sha512,
    MD5: Hash.md5
}


class JWT:
    header = None
    payload = None
    signature = None
    value = None
    salt = None

    @classmethod
    def new(cls, salt: str, expire_in: int = 3000, algorithm: str = 'HS256', **kwargs):
        cls.get_header(algorithm)
        cls.get_payload(expire_in, **kwargs)
        cls.get_signature(cls.header, cls.payload, salt, algorithm)
        cls.value = f'{cls.header}.{cls.payload}.{cls.signature}'
        cls.salt = salt
        return cls

    @classmethod
    def get_header(cls, algorithm: str = 'HS256') -> str:
        cls.header = b64enc({
            'typ': 'JWT',
            'alg': algorithm,
        })
        return cls.header

    @classmethod
    def get_payload(cls, expire_in: int = 3000, **kwargs) -> str:
        cls.payload = b64enc({
            'aut': kwargs.get('author') or 'Mivinci',
            'sub': kwargs.get('subject') or 'Happy',
            'exp': expire_in,
            'iat': int(time.time()),
            'dat': kwargs.get('private_data') or kwargs.get('data') or None
        })
        return cls.payload

    @classmethod
    def get_signature(cls,
        header: str, 
        payload: str, 
        salt: str, 
        algorithm: str = HS256
    ) -> str:
        cls.signature = mapping[algorithm](f'{header}.{payload}', salt)
        return cls.signature

    @classmethod
    def verify(cls,
        token: str,
        salt: str
    ) -> bool:
        try:
            parts = token.split('.')
            header = eval(b64dec(parts[0]))
            payload = eval(b64dec(parts[1]))
            interval = (datetime.now() - datetime.fromtimestamp(payload['iat'])).seconds
            return cls.get_signature(str(parts[0]), str(parts[1]), salt, header['alg']) == parts[2] \
                and interval < payload['exp'] \
                and header['typ'] == 'JWT'
        except:
            return False

    @classmethod
    def separate(cls, token: str) -> Tuple[str, str]:
        return tuple(token.split('.'))

    @classmethod
    def get_private_data(cls, s: str) -> dict:
        if '.' in s:
            return eval(b64dec(s.split('.')[1]))['dat']
        else:
            return eval(b64dec(s))['dat']

    @classmethod
    def self_verify(cls) -> bool:
        return cls.verify(cls.value, cls.salt)  # Only God knows what it is for.


def b64enc(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return base64.b64encode(str.encode(s)).decode()


def b64dec(s: str) -> str:
    return base64.b64decode(s).decode()

from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import typing
import json

PASS = b"12345678901234567890"


def md5(bytestring: bytes, byte_digest: bool):
    digest = MD5.new(bytestring)
    if byte_digest:
        return digest.digest()
    else:
        return digest.hexdigest()


def decryptKdf(passphrase: bytes, salt: bytes) -> bytes:
    concatedPassphrase = passphrase + salt
    md5arr = [0] * 3
    md5arr[0] = md5(concatedPassphrase, True)
    key = md5arr[0]
    for i in range(1, 3):
        md5arr[i] = md5(md5arr[i - 1] + concatedPassphrase, True)
        key += md5arr[i]
    return key[:32]


def encryptKdf(passphrase: bytes):
    salt = get_random_bytes(8)
    salted = b""
    dx = b""
    while len(salted) < 48:
        dx = md5(dx + passphrase + salt, True)
        salted += dx
    key = salted[:32]
    iv = salted[32:32 + 16]
    return key, iv, salt


def aesdecrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt, 16)


def aesencrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, 16))
    return ct


def decrypt(data: typing.Union[dict, str], passphrase: bytes) -> bytes:
    if isinstance(data, str):
        data = json.loads(data)

    key = decryptKdf(passphrase, bytes.fromhex(data['s']))
    return aesdecrypt(key, bytes.fromhex(data['iv']), b64decode(data['ct']))


def encrypt(data: bytes, passphrase: bytes) -> dict:
    key, iv, salt = encryptKdf(passphrase)
    ct = aesencrypt(key, iv, data)
    return {"ct": b64encode(ct), "iv": iv.hex(), "s": salt.hex()}


# quick unittest
pt = b"A plaintext string!"
assert decrypt(encrypt(pt, PASS), PASS) == pt


data = {"ct": "o1WNPOY9bZ9hAwrr/EHh02MA28W8HUhrJyuwjUBDV8I=",
        "iv": "749b0c43e9167f8b59807dc6e5362b78",
        "s": "ba48f438410dfa30"}
print(decrypt(data, PASS).decode('utf8'))

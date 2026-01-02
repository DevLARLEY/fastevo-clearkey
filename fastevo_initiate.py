import base64
import hashlib
import json
import os
import time

import requests
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad


class FastevoInitiate:
    PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArcGlfyUHzXGU+cP3LwNZ
        L5wC3Tpo5i2MeXCNlGR4bB1tnbb2BZ7PHE55S0ypuEDjz8mbeQqLZ3dq76IzV9vE
        QevPPTLe6Kz/VS0j5hBucOwx0kB+/t95kAzJQWinBCzp3FWDqbmiZaP11IP2lOwy
        rx4TPizMbSOJmiVudOUKCzQZ7V3Qe8RLAnHGbOVaLK7PlZHCijt495A9Jh30Vo1d
        0SEFKP9ywuVy0MauScXsWrAwJv/L+jFhYh23fFFESwqvAGqfoSi2vdGwv8m+yHDe
        FekNekO7ee9V5CUdzHuNnYejTdqgcEiW810IwBbjkStFeTe7tzuTj6irbqaWczDE
        4QIDAQAB
        -----END PUBLIC KEY-----"""

    PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC0w5xfznsDlz+G
        c5mI2dOBIhaTNX7aySjS8heyBPYaMwA1cHmVV6fPMIhY3+YDj1osmjcEmiHRN7Fc
        DcG4Kk0U4WD9F0WRmNadJsG5EJ1lBdD3y/fd1bmUGGuy/7chkKDlmobJwirqaHp0
        GU3qWbESL5PeTgQHrW2YSoQi3yWbyl+iN73CPS4Yzfr5xVnJVsdXyifHCzQrVKBs
        NuLAQEaFDYEUxFvjd4scWcsWRQqVjlViJv0soXlsX69H5mRc9aqQgywHP9fEPgNA
        TlYM9R6EkNJ9unb1PH8eOf70EgAl39iMqeSnM2WQi+yjhbReJqS0jxTg56PKdahd
        YfvAyC1fAgMBAAECggEAHJ57u49tWnwvypGy1T/nhKJpAJWPqAQBOqSpq72tWSiJ
        9+v+0+4021DLxYZtXFLt6/HelBPzFrTCl9h1uzq3SX8FZAyzLwILuIXSVgKTaNMq
        6pCYhb64ywGyy3xA+kdzseZtQLRFJyeze34mH9xjdIWj26ZubOjAWUQy93Js+eUj
        xaqfWckQOFT9mmvTyKfcCNbR9/iITUZLtuNz7O91C1xQMVa3k16GTcMfdk6AKuB5
        vAfM3q87bfOdaWN/ACCPPHBnxo8Vq1m8CJytbVpCGf9Q15qoLocDXVk7I7eGBLn9
        /UvxTaHsc0U8nJQrO7Rdf4vt1dxwajIdNDvOkfSMwQKBgQD3dtizxX7qkXxGgai+
        U6NNhEtrtmPhmlX0sz2gEdiyvQrS/b35TmpIZ91ZoKPoSQSzzCXnGhnT8w2en3za
        LwuQGN/jUwf7cInSPC7ZVTEIjrFl5l3373FU9zRq40sR29Ssh4aR5pHZngHA3d1L
        mFzC3r2ofS0DeMtOTff6OSWe6wKBgQC6/8pKBsyfePq2QpY8m4ID+VJBU05MTeuy
        s0UuigDkPgJlHihPx6CpPHHabftfplQ5p1Xv0X25rQ6tDjy5qH9WWNsJxAlfU4Vt
        ja2l63yl8RnHNvRJG+t88Z2+xky17nWweofSz/JrpYU9S0ONr36muPcv8pMxbQnl
        2FIN0o/WXQKBgQDDL66FPUV55v7K7gIW/QlVXv/OGbJ2g7FArQ/ybaEqeglLmnB5
        b+xM5/+jbh1aXh2jY2aR/fhZQOCBOPLVdT39jmEpgJhPLtjGRkn9ikB+q24pHacI
        pIgTqFhj5puTnn0FCHCQK/jmWMaxRU4DDk48NkwJ1ZHnpyNUxBLP/rs5uQKBgQCw
        5ftKjiYSklKyCkmvafjTo47xp0oBmxDmSvqeLQTs5dBEMgQ2fIV6s2iNFs/eyy0Q
        IUGFjase9BxXD4nYpBJZ79K96UpoeE1XtthXhm6zWGJnd5AefSAHYVY1u8ejr8J7
        wV4tynPs63cg5csxBJyOQZntLM+bySe83Ce7Vb6mLQKBgQCnUsyKa9pWfDzUv8PG
        ME4QhUYXhPexY+PAxv+QU9Pm2lIKlpousJPQqx72GPIo4ziKDJZeB6+v0FAcoh4W
        CYjFmuVYoeyVbu5zcz4sx+eTbbb80WTY+Aj144FnPTs0WLruaspLin+cJqjYy26B
        q4g1asuchPANMiVYXeWLaOcPQw==
        -----END PRIVATE KEY-----"""

    def __init__(self):
        # public and private keys do not belong to the same key pair

        self.rsa_encrypt_cipher = PKCS1_OAEP.new(
            RSA.importKey(self.PUBLIC_KEY),
            hashAlgo=SHA256
        )
        self.rsa_decrypt_cipher = PKCS1_OAEP.new(
            RSA.importKey(self.PRIVATE_KEY),
            hashAlgo=SHA256
        )

    @staticmethod
    def _encode_b64(s: bytes) -> str:
        return base64.urlsafe_b64encode(s).decode().strip("=")

    @staticmethod
    def _decode_b64(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "==")

    @staticmethod
    def generate_nonce():
        return str(int(time.time() * 1000)) + os.urandom(16).hex()

    def encrypt_obj(self, data: dict) -> dict:
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        data_payload = pad(json.dumps(data).encode(), AES.block_size)
        encrypted_data = cipher.encrypt(data_payload)

        encrypted_key = self.rsa_encrypt_cipher.encrypt(aes_key)

        return {
            "e": self._encode_b64(encrypted_data),
            "k": self._encode_b64(encrypted_key),
            "i": self._encode_b64(aes_iv)
        }

    def decrypt_obj(self, data: dict) -> dict:
        rsa_ciphertext = self._decode_b64(data["k"])

        aes_key = self.rsa_decrypt_cipher.decrypt(rsa_ciphertext)
        aes_iv = self._decode_b64(data["i"])

        encrypted_data = self._decode_b64(data["e"])
        data_plaintext = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).decrypt(encrypted_data)
        data_unpadded = unpad(data_plaintext, AES.block_size).decode()

        return json.loads(data_unpadded)


if __name__ == '__main__':
    fastevo = FastevoInitiate()

    # token for example video at fastevo.com
    # found in HTML as "data-token"
    PLAY_TOKEN = 'v4.local.9Qr_WssbfGJa0AaaGDEfCjaGGesTXE5-7r5mYV-BZCy_3E-KTBzQ6cRwJZnFlbotVbRvXL1de9iKuJCraGITo-BegmcQJaJFg6YbaaUOyvBKgz256zqcq6Td-s5uRBgu8MuaEsq46hmv2fWHK5uBGuEKSzxqklzhupz5btt6JnDZ-2hru7kqtGM8_mJmiXJP4zz5EIUgELK7jFgXOcjBvl03RnMPFq64wTVTzMdNPlKmEUUZiJp1cB_gx-m9nlnCR1r_BSy-UHU9GsCtxN0Ia3ui-8AcKNtwyMqY542ZTl7LXAFdcZ0hf_pp0Kh-29aUn9spTGlFg9f4iDJfwbI9.eyJ2IjoiMSIsInAiOiI2NzE5NWY1NTlmZjkxNzllODVlMWE2YmQifQ'

    CLIENT_DATA = {
        "clientDetails": {
            "browser": {
                "major": "142",
                "name": "Edge",
                "version": "142.0.3595.94"
            },
            "cpu": {
                "architecture": "amd64"
            },
            "device": {
                "type": "desktop"
            },
            "deviceMemory": 8,
            "engine": {
                "name": "Blink",
                "version": "142.0.7444.176"
            },
            "gpuDetails": {
                "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 2080 Ti (0x00001E07) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "vendor": "Google Inc. (NVIDIA)"
            },
            "hardwareConcurrency": 12,
            "isInsideIframe": True,
            "language": "en-US",
            "maxTouchPoints": 0,
            "os": {
                "name": "Windows",
                "version": "11"
            },
            "referer": "https://fastevo.com/",
            "timeZone": "Europe/Berlin",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
        },
        "clientVersion": "1.0.415",
        "nonce": fastevo.generate_nonce(),
        "operatingSystem": "Windows",
        "playTokenHash": hashlib.sha256(PLAY_TOKEN.encode()).hexdigest(),
        "storageBasedIdentityClaim": None,
        "supportedDRMSystems": [
            "org.w3.clearkey"
        ]
    }

    encrypted_obj = fastevo.encrypt_obj(CLIENT_DATA)

    response = requests.post(
        url='https://api.fastevo.net/service/api/v1/mediaprotection/playback/initiate',
        headers={
            'authorization': PLAY_TOKEN,
            'content-type': 'application/json'
        },
        data=json.dumps(encrypted_obj),
    )

    print(response.status_code)

    decrypted_obj = fastevo.decrypt_obj(response.json())
    clearkeys = decrypted_obj["playbackData"]["protectionDetails"]["clearKeys"]

    key_str = "".join(list(map(
        lambda ck: f"--key {ck['keyId']}:{ck['key']} ",
        clearkeys
    ))).strip()

    print(f"N_m3u8DL-RE \"{decrypted_obj["playbackData"]["mediaPlaylistUrl"]}\" {key_str} -M format=mkv --use-shaka-packager")
from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode


def xor(in1, in2):
    ret = []
    for i in range(0, max(len(in1), len(in2))):
        ret.append(in1[i % len(in1)] ^ in2[i % len(in2)])
    return bytes(ret)


def decrypt_aes_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def encrypt_aes_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def pkcs7(val, block_size=16):
    remaining = block_size - len(val) % block_size

    if remaining == block_size:
        remaining = 16
    ret = val + chr(remaining).encode() * remaining

    return ret


def unpkcs7(val):
    pad_amount = val[-1]
    if pad_amount == 0:
        raise Exception
    for i in range(len(val) - 1, len(val) - (pad_amount + 1), -1):
        if val[i] != pad_amount:
            raise Exception
    return val[:-pad_amount]


def decrypt_aes_cbc(data, key, iv=b'\x00' * 16, pad=True):
    prev_chunk = iv

    decrypted = []

    for i in range(0, len(data), 16):
        chunk = data[i: i + 16]
        decrypted += xor(decrypt_aes_ecb(chunk, key), prev_chunk)
        prev_chunk = chunk

    if pad:
        return unpkcs7(bytes(decrypted))
    return bytes(decrypted)


def encrypt_aes_cbc(data, key, iv=b'\x00' * 16, pad=True):
    if pad:
        padded = pkcs7(data)
    else:
        padded = data

    prev_chunk = iv

    encrypted = []

    for i in range(0, len(padded), 16):
        chunk = padded[i: i + 16]
        encrypted_block = encrypt_aes_ecb(xor(chunk, prev_chunk), key)
        encrypted += encrypted_block
        prev_chunk = encrypted_block

    return bytes(encrypted)


file1 = open("lorem.txt", "r+")
file1_input = file1.read()

result = encrypt_aes_cbc(file1_input.encode("utf8"), b"TIANANMEN SQUARE")
result = b64encode(result).decode()
print(result)

decrypted_txt = decrypt_aes_cbc(b64decode(result), b"TIANANMEN SQUARE")
print(decrypted_txt)
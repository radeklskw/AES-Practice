import struct
import time
from Crypto.Util import Counter
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

'''
cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
decipher = AES.new(key.encode("utf8"),AES.MODE_ECB)
maly = open("polMB.txt","r")
sredni = open("8MB.txt","r")
duzy = open("400MB.txt","r")
maly1 = maly.read()
sredni1 = sredni.read()
duzy1 = duzy.read()
maly_szyfr_start_ECB = time.time()
msg = cipher.encrypt(maly1.encode("utf8"))
maly_szyfr_stop_ECB = time.time() - maly_szyfr_start_ECB

maly_deszyfr_start_ECB = time.time()
msg1 = cipher.decrypt(msg)
maly_deszyfr_stop_ECB = time.time() - maly_deszyfr_start_ECB

print("Szyfrowanie malego fileu ECB: " + str(maly_szyfr_stop_ECB) + "\n")
print("Deszyfrowanie malego fileu ECB: " + str(maly_deszyfr_stop_ECB) + "\n")

sredni_szyfr_start = time.time()
msg2 = cipher.encrypt(sredni1.encode("utf8"))
maly_szyfr_stop = time.time() - sredni_szyfr_start

maly_deszyfr_start = time.time()
msg1 = cipher.decrypt(msg)
maly_deszyfr_stop = time.time() - maly_deszyfr_start
'''

def encrypt_ECB(file, key):
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    start_time = time.time()
    encrypted_text = b64encode(cipher.encrypt(pad(file.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Encryption time (ECB): " + str(end_time))
    return encrypted_text


def decrypt_ECB(file, key):
    raw = b64decode(file)
    decipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    start_time = time.time()
    decrypted_text = unpad(decipher.decrypt(raw), 16)
    end_time = time.time() - start_time
    print("Decryption time (ECB): " + str(end_time))
    return decrypted_text


def encrypt_CBC(file, key):
    cipher = AES.new(key.encode("utf8"), AES.MODE_CBC, iv)
    start_time = time.time()
    encrypted_text = b64encode(iv + cipher.encrypt(pad(file.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Encryption time (CBC): " + str(end_time))
    return encrypted_text


def decrypt_CBC(file, key):
    raw = b64decode(file)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CBC, iv)
    start_time = time.time()
    decrypted_text = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Decryption time (CBC): " + str(end_time))
    return decrypted_text


def encrypt_OFB(file, key):
    cipher = AES.new(key.encode("utf8"), AES.MODE_OFB, iv)
    start_time = time.time()
    encrypted_text = b64encode(iv + cipher.encrypt(pad(file.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Encryption time (OFB): " + str(end_time))
    return encrypted_text


def decrypt_OFB(file, key):
    raw = b64decode(file)
    decipher = AES.new(key.encode("utf8"), AES.MODE_OFB, iv)
    start_time = time.time()
    decrypted_text = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Decryption time (OFB): " + str(end_time))
    return decrypted_text


def encrypt_CFB(file, key):
    cipher = AES.new(key.encode("utf8"), AES.MODE_CFB, iv)
    start_time = time.time()
    encrypted_text = b64encode(iv + cipher.encrypt(pad(file.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Encryption time (CFB): " + str(end_time))
    return encrypted_text


def decrypt_CFB(file, key):
    raw = b64decode(file)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CFB, iv)
    start_time = time.time()
    decrypted_text = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Decryption time (CFB): " + str(end_time))
    return decrypted_text


def encrypt_CTR(file, key):
    cipher = AES.new(key.encode("utf8"), AES.MODE_CTR, counter=counter)
    start_time = time.time()
    encrypted_text = b64encode(iv + cipher.encrypt(pad(file.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Encryption time (CTR): " + str(end_time))
    return encrypted_text


def decrypt_CTR(file, key):
    raw = b64decode(file)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CTR, counter=counter)
    start_time = time.time()
    decrypted_text = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Decryption time (CTR): " + str(end_time))
    return decrypted_text


key = 'abcdefghijklmnop'
iv = b'0000000000000000'
counter = Counter.new(128, initial_value=int(iv, 16))

small = open("smalltext.txt", "r")
small1 = small.read()

medium = open("mediumtext.txt", "r")
medium1 = medium.read()

big = open("bigtext.txt", "r")
big1 = big.read()


print("\nSmall file: ")
s1 = encrypt_ECB(small1, key)
d1 = decrypt_ECB(s1, key)

s2 = encrypt_CBC(small1, key)
d2 = decrypt_CBC(s2, key)
#f = open("smallCBCerr.txt", "x")
#f.write(str(s2))
#f.close()

s3 = encrypt_OFB(small1, key)
d3 = decrypt_OFB(s3, key)
#f = open("smallOFBerr.txt", "x")
#f.write(str(s3))
#f.close()

s4 = encrypt_CFB(small1, key)
d4 = decrypt_CFB(s4, key)
#f = open("smallCFBerr.txt", "x")
#f.write(str(s4))
#f.close()

s5 = encrypt_CTR(small1, key)
d5 = decrypt_CTR(s5, key)
#f2 = open("smallCTRerr.txt", "x")
#f2.write(str(s5))
#f2.close()

'''
print("\nMedium file: ")
m1 = encrypt_ECB(medium1, key)
d6 = decrypt_ECB(m1, key)

m2 = encrypt_CBC(medium1, key)
d7 = decrypt_CBC(m2, key)

m3 = encrypt_OFB(medium1, key)
d8 = decrypt_OFB(m3, key)

m4 = encrypt_CFB(medium1, key)
d9 = decrypt_CFB(m4, key)

m5 = encrypt_CTR(medium1, key)
d10 = decrypt_CTR(m5, key)


print(" \nBig file:")
b1 = encrypt_ECB(big1, key)
d11 = decrypt_ECB(b1, key)

b2 = encrypt_CBC(big1, key)
d12 = decrypt_CBC(b2, key)

b3 = encrypt_OFB(big1, key)
d13 = decrypt_OFB(b3, key)

b4 = encrypt_CFB(big1, key)
d14 = decrypt_CFB(b4, key)

b5 = encrypt_CTR(big1, key)
d15 = decrypt_CTR(b5, key)
'''

#checking what's wrong with errors in cryptogram
file1 = open("smallECBerr.txt")
file1_inside = file1.read()
b_file1_inside = bytes(file1_inside, 'utf-8')
d_err = decrypt_ECB(b_file1_inside, key)
output = open("decrypted_with_error.txt", "w")
output.write(str(d_err))
output.close()

#file2 = open("smallCBCerr.txt")
#file2_inside = file2.read()
#b_file2_inside = bytes(file2_inside, 'utf-8')
#d_err2 = decrypt_CBC(b_file2_inside, key)
## kilka bloków zostaje zmienionych

#file3 = open("smallCFBerr.txt")
#file3_inside = file3.read()
#b_file3_inside = bytes(file3_inside, 'utf-8')
#d_err3 = decrypt_CFB(b_file3_inside, key)
##również kilka bloków zostaje zmienionych

#file4 = open("smallCTRerr.txt")
#file4_inside = file4.read()
#b_file4_inside = bytes(file4_inside, 'utf-8')
#d_err4 = decrypt_CTR(b_file4_inside, key)
##zmiena jednego bitu powoduje błędy tylko w jednym bajcie

#file5 = open("smallOFBerr.txt")
#file5_inside = file5.read()
#b_file5_inside = bytes(file5_inside, 'utf-8')
#d_err5 = decrypt_OFB(b_file5_inside, key)
##zmiana jednego bitu powoduje błędy tylko w jednym bajcie

#here1
#x1 = open("inne_ECB.txt", "r+")
#x2 = x1.read()
#x3 = deszyfrowanie_ECB(x2, key)
#print(x3)
#end here
##zmiana w szyfrogramie metoda ECB powoduje znieksztalcenie kilka blokow
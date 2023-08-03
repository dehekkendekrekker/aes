from Crypto.Cipher import AES
import hashlib

hash = hashlib.sha512(b'secret').digest()
key  = hash[0:32]  # bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d68
iv   = hash[32:48] # 2ce56b4d64a9ef097761ced99e0f6726
print ("Key: %s" % key.hex())
print ("IV:  %s" % iv.hex())

cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
ct = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
# ffffffffffffffffffffffffffffffff
plaintext = cipher.decrypt(ct)
print("PT:  %s" % plaintext.hex()) # c2a5696851d90567619d102900a90905
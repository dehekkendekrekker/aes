from Crypto.Cipher import AES
import hashlib

hash = hashlib.sha512(b'secret').digest()
key  = hash[0:32]  # bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d68
print ("Key: %s" % key.hex())

cipher = AES.new(key=key, mode=AES.MODE_CBC)
ct = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
# ffffffffffffffffffffffffffffffff
plaintext = cipher.decrypt(ct)
print("PT: %s" % plaintext.hex()) # ee4002253570ea6e16fcdef09ea66e23
from Crypto.Cipher import AES
import hashlib

hash = hashlib.sha512(b'secret').digest()
key  = hash[0:32]
iv   = hash[32:48]
print ("Key: %s" % key.hex())
print ("IV:  %s" % iv.hex())

cipher = AES.new(key=key, mode=AES.MODE_ECB)
ct = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
# ffffffffffffffffffffffffffffffff
print (len(ct))
plaintext = cipher.decrypt(ct)

print("PT: %s" % plaintext.hex()) # ee4002253570ea6e16fcdef09ea66e23
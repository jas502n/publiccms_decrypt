from pyDes import *
import hashlib
import base64

def get_sha1(res:str):
    import hashlib
    """
    使用sha1加密算法，返回str加密后的字符串
    """
    sha = hashlib.sha1(res.encode('utf-8'))
    encrypts = sha.hexdigest()
    return encrypts[0:24]

def publiccms_decrypt(data, key):
    # key1 = "2435e960d9be985705455019cfd3bc84c39344db"[0:24]
    keys = get_sha1(key)
    print("[+] Key= " + keys)
    data = base64.b64decode(data)
    k = triple_des(keys, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    e = k.decrypt(data)
    return e.decode("utf-8")


data = "9xgiKaPSBm9y76PsUC+0Ig=="
key = "publiccms"

print("[+] EncryptData= " + data)
print("[+] PlainText= " + publiccms_decrypt(data, key))
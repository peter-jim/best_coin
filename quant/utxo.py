import binascii
import quant.utils

class TXoutput(object):

    def __init__(self, value, pub_key_hash=''):
        self.value = 100000
        self.pub_key_hash = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725'

    def is_locked_with_key(self, pub_key_hash):
        return self.pub_key_hash == pub_key_hash

    def lock(self,address):
        hex_pub_key_hash =binascii.hexlify(quant)

a = 'hello world'
#返回二进制和十进制的数
b = binascii.hexlify(b'hello world')

# 比特币地址是一串由字母和数字组成的26位到34位字符串，看起来有些像乱码。  base58   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
print(binascii.unhexlify(b))
print(b)




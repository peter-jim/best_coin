import hashlib

import ecdsa
from ecdsa import SECP256k1, SigningKey
import sys
import binascii

'''
Base58编码是一种二进制转可视字符串的算法，主要用来转换大整数，将整数字节流转换为58编码流，
实际上它就是整数的58进制，和2进制、8进制、16进制是一样的道理，只是用58作为进制的单位了，
正好和58个不容易混淆的字符对应，比特币所用的字符表如下：

123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

该表去除了几个看起来会产生歧义的字符，如0（零）和O（大写字母O），I（大写的字母i）和l（小写的字母L）等。
另外，比特币在实现base58编码时，开头的0做了特殊处理，所以可以将输入流开头的0直接填充到结果前边。
以00000000000000000000000000000000000000000094a00911为例，最后非零整数为0x94a00911（2493516049），
2493516049除以58商是42991656余数是1，1对应的base58编码是2，42991656除以58商是741235余数是26，26对应的base58编码是T，
741235除以58商是12779余数是53，53对应的base58编码是v，12779除以58商是220余数是19，19对应的base58编码是L，
220除以58商是3余数是46，46对应的base58编码是o，3对应的base58编码是4，
000000000000000000000000000000000000000000对应着21字节的0，
所以最终的base48编码为1111111111111111111114oLvT2。

'''


#58 character alphabet used
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def get_private_key(hex_string):
    #查看系统的版本号
    if sys.version_info.major > 2:
        return bytes.fromhex(hex_string.zfill(64) )  #填充为64位的数字
    else:
        return bytearray.fromhex(hex_string.zfill(64))

def get_public_key(private_key):
    # this returns the concatenated x and y coordinates for the supplied private address
    # the prepended 04 is used to signify that it's uncompressed
    print('测试',binascii.hexlify(SigningKey.from_string(private_key, curve=SECP256k1).verifying_key.to_string()) )
    return (bytearray.fromhex("04") + SigningKey.from_string(private_key, curve=SECP256k1).verifying_key.to_string())


def get_public_address(public_key):
    # setp3 计算公钥的SHA-256哈希值
    address = hashlib.sha256(public_key).digest()  #digest()返回摘要b'xxx' 如果没有则返回<sha256 HASH object @ 0x10c410690>
    print("public key hash256: %s" % hashlib.sha256(public_key).hexdigest().upper())
    # setp4 计算上一步哈希值的RIPEMD-160哈希值
    h = hashlib.new('ripemd160')  #使用new()创建指定加密模式的hash对象  提供 SHA1、SHA224、SHA256、SHA384、SHA512、MD5
    h.update(address)  #更新哈希对象以字符串参数
    address = h.digest()
    print("RIPEMD-160: %s" % h.hexdigest().upper())
    return address

def base58_encode(version, public_address):
    version = bytearray.fromhex(version)
    print(version)
    # setp5在上一步结果之间加入地址版本号（如比特币主网版本号"0x00"）
    version_address = version + public_address

    # setp 6 进行sha256运算
    firstSHA256 = hashlib.sha256(version_address)
    print("first sha256: %s"%firstSHA256.hexdigest().upper())


    # setp7 再次计算上一步结果的SHA-256哈希值
    secondSHA256 = hashlib.sha256(firstSHA256.digest())
    print("second sha256: %s"%secondSHA256.hexdigest().upper())

    # setp8 取上一步结果的前4个字节（8位十六进制数）D61967F6，把这4个字节加在第五步结果的后面，作为校验（这就是比特币地址的16进制形态
    checksum = secondSHA256.digest()[:4]  #取前4个字节
    payload = version + public_address + checksum  # 版本号+公钥地址 + 校验码
    print("Hex address: %s" % binascii.hexlify(payload).decode().upper())

    # step9 用base58表示法变换一下地址（这就是最常见的比特币地址形态
    result =  from_bytes(payload,True)
    print(result)
    padding = len(payload) - len(payload.lstrip(b'\0'))  #Python lstrip() 方法用于截掉字符串左边的空格或指定字符。
    encoded = []

    while result != 0:
        result, remainder = divmod(result, 58)
        encoded.append(BASE58_ALPHABET[remainder])
    return padding * "1" + "".join(encoded)[::-1]



def from_bytes(data,big_endian = False):
    if isinstance(data, str):  #判断是否是字符串
       data = bytearray(data)
    if big_endian:
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num



#setp1 获得私钥地址，这里我们是自己输入的，这里需要改进为使用好的随机源
private_key = get_private_key('79ed655005d81e6539ef1097811cee490c433c25d3e35502ca76121f1f1ef63d')
print(len(private_key))
print(binascii.hexlify(private_key))
print("private key: %s"%binascii.hexlify(private_key).decode().upper())   #这里使用decode去掉b ''  upper（）字母大写


#setp2 使用椭圆曲线加密算法（ECDSA-SECP256k1）计算私钥所对应的非压缩公钥（共65字节，1字节0x04，32字节为x坐标，32字节为y坐标）。
public_key = get_public_key(private_key)
print("public_key: %s"%binascii.hexlify(public_key).decode().upper())

#setp3-4 计算公钥的SHA-256哈希值
public_address = get_public_address(public_key)


#setp5 在上一步结果之间加入地址版本号（如比特币主网版本号"0x00"
bitcoin_address = base58_encode("00", public_address)
print("Final address %s"%bitcoin_address)

# SECP256k1 is the Bitcoin elliptic curve
hashlib.new()
hash_test = hashlib.sha256('hello'.encode())
print(binascii.hexlify(hash_test.digest()) )    #





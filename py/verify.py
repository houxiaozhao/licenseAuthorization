from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as pk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from loguru import logger
import base64
import json
import os
import sys

 
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def aesDecrypt(key, data):
    '''
    :param key: 密钥
    :param data: 加密后的数据（密文）
    :return:明文
    '''
    key = key.encode('utf8')
    data = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)

    # 去补位
    text_decrypted = unpad(cipher.decrypt(data))
    text_decrypted = text_decrypted.decode('utf8')
    # print(text_decrypted)
    return text_decrypted

def gethardinfo():
    """获取硬件信息"""
    gpu_id = None
    cpu_id = None

    # 获取 GPU UUID
    try:
        c = os.popen('nvidia-smi -q')
        output = c.read()
        c.close()
        lines = list(map(lambda x: x.strip(), output.split('\n')))
        for line in lines:
            if line.startswith('GPU UUID'):
                gpu_id = line.split(':')[1].strip()
                logger.debug(f"Found GPU UUID: {gpu_id}")
                break
    except Exception as e:
        logger.warning(f"GPU UUID verify Error: {e}")

    # 获取 CPU ID
    try:
        system_id = os.popen("dmidecode -s system-uuid").read().strip()
    except Exception as e:
        logger.warning(f"system_id verify Error: {e}")

    if not gpu_id or not system_id:
        logger.error("Failed to get either GPU UUID or CPU ID")
        return None

    # 组合硬件ID
    hardware_id = f"{gpu_id}_{system_id}"
    # logger.debug(f"Combined hardware ID: {hardware_id}")
    return hardware_id

def verify(license, publicKey, appid, isfile=False)->bool:
    print(license, publicKey, appid, isfile)
    """
    使用license、公钥、appid进行权限验证

    【默认】可以直接传入相应的文件内容（字符串），【参数设定】也可以传入相应的文件路径
    如果传入的是文件，则需要 isfile=True
    """
    try:
        if isfile:
            logger.debug("Reading files...")
            if os.path.exists(license) and os.path.exists(publicKey) and os.path.exists(appid):
                with open(license,'r') as f:
                    license = f.read().strip()
                with open(publicKey,'r') as f:
                    publicKey = f.read().strip()
                with open(appid,'r') as f:
                    appid = f.read().strip()
            else:
                logger.error("One or more files do not exist")
                return False

        # 解析许可证内容
        aesKey = license[:16]
        encDataLength = int(license[16:18], 16)
        encData = license[18:18+encDataLength]
        sign = license[18+len(encData):]

        # logger.debug("\nLicense content breakdown:")
        # logger.debug(f"Total license length: {len(license)}")
        # logger.debug(f"AES Key: {aesKey}")
        # logger.debug(f"Encrypted Data Length (hex): {license[16:18]}")
        # logger.debug(f"Encrypted Data Length (int): {encDataLength}")
        # logger.debug(f"Encrypted Data: {encData[:50]}...")
        # logger.debug(f"Encrypted Data length: {len(encData)}")
        # logger.debug(f"Signature: {sign[:50]}...")
        # logger.debug(f"Signature length: {len(sign)}")

        try:
            # 解码签名
            signature = base64.b64decode(sign)
            # logger.debug(f"Decoded signature length: {len(signature)} bytes")
            # logger.debug(f"Decoded signature: {signature.hex()[:50]}...")  # 显示部分十六进制内容
            
            # 验证签名长度
            key = RSA.importKey(publicKey)
            expected_length = key.size_in_bytes()
            if len(signature) != expected_length:
                # logger.error(f"Invalid signature length. Expected {expected_length} bytes, got {len(signature)} bytes")
                # logger.debug(f"Full signature before base64 decode: {sign}")
                return False

            # 尝试导入公钥
            key = RSA.importKey(publicKey)
            # logger.debug("Public key imported successfully")
            # logger.debug(f"Public key size: {key.size_in_bits()} bits")
            
            # 创建验证器
            pubkey = pk.new(key)
            
            # 创建哈希对象
            hash_obj = SHA256.new(base64.b64decode(encData))
            # logger.debug(f"Hash value: {hash_obj.hexdigest()}")
            
            # 验证签名
            try:
                if pubkey.verify(hash_obj, signature):
                    logger.info("Signature verification successful")
                else:
                    logger.error("Signature verification failed")
                    return False
            except Exception as e:
                logger.error(f"Signature verification error: {e}")
                return False

        except Exception as e:
            logger.error(f"Verification process error: {str(e)}")
            return False

        # 如果验证通过，继续处理
        try:
            jsontext = aesDecrypt(aesKey, encData)
            # logger.debug(f"Decrypted JSON: {jsontext}")
            
            info = json.loads(jsontext)
            logger.debug(f"License hardware info: {info}")
            
            hardinfo = gethardinfo()
            
            # logger.debug(f"License hardware info: {info['hardware']}")
            # logger.debug(f"Current hardware info: {hardinfo}")
            
            if info['appid'] == appid and info["hardware"].upper() == hardinfo.upper():
                logger.info("License verification successful")
                return True
            else:
                logger.error("Hardware info verification failed")
                return False
                
        except Exception as e:
            # logger.error(f"Data processing error: {str(e)}")
            return False
            
    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        return False


print(verify('/Users/axyw/Documents/project/authorization/py/key/license', '/Users/axyw/Documents/project/authorization/py/key/publicKey.pem', '/Users/axyw/Documents/project/authorization/py/key/appid',isfile=True))
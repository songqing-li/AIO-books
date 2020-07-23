#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

import base64
import rsa
from rsa import common

#使用rsa库进行RSA签名和加解密
class RSAUtil(object):
	PUBLIC_KEY_PATH = 'C:\\OpenSSL-Win64\\bin\\rsa_public_key.pem' #公钥路径
	PRIVATE_KEY_PATH = 'C:\\OpenSSL-Win64\\bin\\rsa_private_key.pem' #私钥路径
	#初始化key
	def __init__(self,
			company_pub_file=PUBLIC_KEY_PATH,
			company_pri_file=PRIVATE_KEY_PATH):

		if company_pub_file:
			self.company_public_key = rsa.PublicKey.load_pkcs1_openssl_pem(open(company_pub_file).read())
		if company_pri_file:
			self.company_private_key = rsa.PrivateKey.load_pkcs1(open(company_pri_file).read())

	def get_max_length(self, rsa_key, encrypt=True):
		'''如果加密内容过长，就分段加密，换算每一段的长度.
			:param rsa_key: 密钥
			：param encrypt: 是否加密
		'''
		blocksize = common.byte_size(rsa_key.n)
		reserve_size = 11 #预留位
		if not encrypt:
			reserve_size = 0 #解密不需要预留位
		maxlength = blocksize - reserve_size
		return maxlength

	#公钥加密
	def encrypt_by_public_key(self, message):
		'''
		   :param message: 需要加密的内容
		   加密后进行base64转码
		'''
		encrypt_result = b''
		max_length = self.get_max_length(self.company_public_key)
		while message:
			input = message[:max_length]
			message = message[max_length:]
			out = rsa.encrypt(input, self.company_public_key)
			encrypt_result += out
		encrypt_result = base64.b64encode(encrypt_result)
		return encrypt_result
    #私钥解密
	def decrypt_by_private_key(self, message):
		'''
		   ：param message: 需要解密的内容
		    解密之后为字符串不需要转义
		'''
		decrypt_result = b''

		max_length = self.get_max_length(self.company_private_key, False)
		decrypt_message = base64.b64decode(message)
		while decrypt_message:
			input = decrypt_message[:max_length]
			decrypt_message = decrypt_message[max_length:]
			out = rsa.decrypt(input, self.company_private_key)
			decrypt_result += out
		return decrypt_result

def main():
	message = bytes(input('please input message: '), encoding='utf-8')
	print('complaintext:\n', str(message, encoding='utf-8'))
	rsaUtil = RSAUtil()
	encrypt_result = rsaUtil.encrypt_by_public_key(message)
	print('encrypt_result:', encrypt_result, 'type:', type(encrypt_result))
	decrypt_result = rsaUtil.decrypt_by_private_key(encrypt_result)
	print('decrypt_result:', decrypt_result, 'type:', type(decrypt_result))

if __name__ == '__main__':
	main()
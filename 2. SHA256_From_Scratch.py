import hashlib
import json
import math
import os
import random
import string
import time


def rrot(num: int, by: int, wrap=True) -> int:

	if wrap is False:
		return num >> by

	return (num >> by)|(num << (32 - by)) & 0xFFFFFFFF



def lrot(num: int, by: int, wrap=True) -> int:

	if wrap is False:
		return num << by

	return (num << by)|(num >> (32 - by))




def xor(a: int, b: int) -> int:
	return a ^ b




def sigma_lc_0(inp_arr: int) -> int:




	"""Implements Right rotation (7 and 18) and shift (3) on the given number then xor's the results and returns final number"""

	r_rot_seven = rrot(num=inp_arr, by=7, wrap=True)
	r_rot_eighteen = rrot(num=inp_arr, by=18, wrap=True)
	sh_rit_three = rrot(num=inp_arr, by=3, wrap=False)

	return xor(xor(r_rot_seven, r_rot_eighteen), sh_rit_three)




def sigma_lc_1(inp_arr: int) -> int:


	"""Implements Right rotation (17 and 19) and shift (10) on the given number then xor's the results and returns final number"""


	r_rot_seventeen = rrot(num=inp_arr, by=17, wrap=True)
	r_rot_nineteen = rrot(num=inp_arr, by=19, wrap=True)
	sh_rit_ten = rrot(num=inp_arr, by=10, wrap=False)

	return xor(xor(r_rot_seventeen, r_rot_nineteen), sh_rit_ten)




def sigma_uc_0(inp_arr: int) -> int:


	"""Implements Right rotation (2 and 13 and 22) on the given number then xor's the results and returns final number"""


	r_rot_two = rrot(num=inp_arr, by=2, wrap=True)
	r_rot_thirteen = rrot(num=inp_arr, by=13, wrap=True)
	rot_rit_twotwo = rrot(num=inp_arr, by=22, wrap=True)

	return xor(xor(r_rot_two, r_rot_thirteen), rot_rit_twotwo)




def sigma_uc_1(inp_arr: int) -> int:


	"""Implements Right rotation (6 and 11 and 25) on the given number then xor's the results and returns final number"""


	r_rot_six = rrot(num=inp_arr, by=6, wrap=True)
	r_rot_eleven = rrot(num=inp_arr, by=11, wrap=True)
	rot_rit_twofive = rrot(num=inp_arr, by=25, wrap=True)

	return xor(xor(r_rot_six, r_rot_eleven), rot_rit_twofive)




def majority(a: int, b: int, c: int) -> int:

	# result = (a & b) | (b & c) | (c & a)
	result = (a & (b | c)) | (b & c)
	
	return result




def choice(a: int, b: int, c: int) -> int:

	return (a & b) ^ (~a & c)




def as_32bit(x: int) -> str:
	return f"{x:032b}"




def generate_primes_croots() -> 'list[int]':

	"""Generates cuberoots of first 64 prime numbers"""

	# primes =  [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311]

	# cuberoot = [(x ** (1/3)) for x in primes]

	# hexes = []

	# bins = []

	# for x in cuberoot:
	# 	a = (hex(math.floor(math.modf(x)[0] * (2**32))))
	# 	hexes.append(a)
	# 	bins.append(f"{int(a, base=16):032b}")



	# return bins

	return [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]
	



def generate_primes_sroots() -> 'list[int]':
	"""Generates  square roots of first 8 prime numbers"""

	# primes =  [2, 3, 5, 7, 11, 13, 17, 19]

	# cuberoot = [math.sqrt(x) for x in primes]

	# hexes = []

	# bins = []

	# for x in cuberoot:
	# 	a = (hex(math.floor(math.modf(x)[0] * (2**32))))
	# 	hexes.append(a)
	# 	bins.append(f"{int(a, base=16):032b}")



	# return bins

	return [
		0x6a09e667, 0xbb67ae85, 
		0x3c6ef372, 0xa54ff53a, 
		0x510e527f, 0x9b05688c, 
		0x1f83d9ab, 0x5be0cd19
		]




def pad_message(msg_in_bin: str) -> str:

	orig_len = len(msg_in_bin)

	msg_in_bin += "1"

	k = 0

	while (orig_len + 1 + k + 64) % 512 != 0:
		k += 1

	for i in range(k):
		msg_in_bin += "0"

	msg_in_bin += f"{orig_len:064b}"

	return msg_in_bin




def sha256(message: bytes) -> str:

	# To save execution time, initializing the variable
	prime_cube_roots = generate_primes_croots()
	prime_square_roots = generate_primes_sroots()


	# Initialize hash values
	h0 = prime_square_roots[0]
	h1 = prime_square_roots[1]
	h2 = prime_square_roots[2]
	h3 = prime_square_roots[3]
	h4 = prime_square_roots[4]
	h5 = prime_square_roots[5]
	h6 = prime_square_roots[6]
	h7 = prime_square_roots[7]


	# When we use bytes as input message type
	message_chars_bin = [f"{(letter):08b}" for letter in message]
	message_chars_bin = "".join(message_chars_bin)

	# Padding the message
	padded_message = pad_message(message_chars_bin)


	message_chunks: 'list[str]' = []

	for i in range(0, len(padded_message), 512):
		message_chunks.append(padded_message[i:i+512])

	# print(json.dumps(message_chunks, indent=4))


	# Creating a 64-entry message schedule array of 32-bit words (represented by W[0,1,2,3...,63])
	for i, chunk in enumerate(message_chunks):

		# print("Processing chunk: ", i)

		# Creating message schedule
		message_schedule: 'list[str]' = []


		# Split the chunk into 32 bit words and append the words to message schedule
		for i in range(0, len(chunk), 32):
			message_schedule.append(chunk[i:i+32])




		# Extend the first 16 words into the remaining 48 words W[16..63] of the message schedule array:
		for i in range(16, 64):

			# print(message_schedule[i-2])
			# print(message_schedule[i-7])
			# print(message_schedule[i-15])
			# print(message_schedule[i-16])


			w = sigma_lc_1(int(message_schedule[i-2], base=2))
			x = int(message_schedule[i-7], base=2)
			y = sigma_lc_0(int(message_schedule[i-15], base=2))
			z = int(message_schedule[i-16], base=2)

			# e = f"{((int(w, base=2) + int(x, base=2) + int(y, base=2) + int(z, base=2)) % (2**32)):032b}"
			word = (w + x + y + z) % 2**32


			# print(word)

			message_schedule.append(as_32bit(word))

		# Initialize working variables to current hash value
		a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

		# print(json.dumps(message_schedule, indent=4))

		# Compression loop
		for i in range(len(message_schedule)):
			# print()
			# print(f"W{i} = {message_schedule[i]}", end="\n")
			# print(f"K{i} = {generate_primes_croots()[i]}", end="\n")
			# print()

			temp1 = (sigma_uc_1(e) + choice(e, f, g) + h + prime_cube_roots[i] + int(message_schedule[i], base=2)) % 2**32
			temp2 = (sigma_uc_0(a) + majority(a, b, c)) % 2**32





			h = g
			g = f
			f = e
			e = d
			d = c
			c = b
			b = a

			e = (e + temp1) % 2**32
			a = (temp1 + temp2) % 2**32



		# Add the compressed chunk to the current hash value:
		h0 = (h0 + a) % 2**32
		h1 = (h1 + b) % 2**32
		h2 = (h2 + c) % 2**32
		h3 = (h3 + d) % 2**32
		h4 = (h4 + e) % 2**32
		h5 = (h5 + f) % 2**32
		h6 = (h6 + g) % 2**32
		h7 = (h7 + h) % 2**32

	hex_digest = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}{h5:08x}{h6:08x}{h7:08x}"
	# hex_digest = f"{h0:08x} {h1:08x} {h2:08x} {h3:08x} {h4:08x} {h5:08x} {h6:08x} {h7:08x}"
	

	return hex_digest
	
	return hex_digest, bytes.fromhex(hex_digest)






if __name__ == "__main__":


	print()
	print()

	data = os.urandom(10**3)

	print(f"Hashlib Hash Value:         {hashlib.sha256(data).hexdigest()}")
	print(f"Current implementation:     {sha256(data)}")

	print(hashlib.sha256(data).hexdigest() == sha256(data))

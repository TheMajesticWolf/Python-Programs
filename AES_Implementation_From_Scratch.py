import os
import pprint
import tkinter.filedialog as tfdg
import ctypes



ctypes.windll.shcore.SetProcessDpiAwareness(2)

# By TheMajesticWolf 26/04/2023

# Resources, References
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
# https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
# https://crypto.stackexchange.com
# https://github.com/boppreh/aes/blob/master/aes.py
# https://github.com/m3y54m/aes-in-c/blob/main/README.md
# https://github.com/kokke/tiny-AES-c
# https://github.com/bozhu/AES-Python/blob/master/aes.py
# https://www.youtube.com/@ChiragBhalodia
# https://www.youtube.com/@Computerphile
#
#

s_box = (
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

rcon = (
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
	0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
	0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
	0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)



def transpose(matrix):

	c = [[0 for j in range(len(matrix))] for i in range(len(matrix[0]))]

	for i in range(len(matrix)):
		for j in range(len(matrix[0])):
			c[j][i] = matrix[i][j]



	return c


def bytes_to_matrix(data: 'bytes'):
	"""
	Converts a byte string of length 16 into a 4x4 matrix (row major) i.e the first 4 elements form the 1st row
	the next 4 elements form the 2nd row
	"""
	c = 0
	final = []
	for i in range(4):
		temp = []
		for j in range(4):
			temp.append(data[c])
			c += 1
		final.append(temp)

	# final = [list(data[i:i+4]) for i in range(0, 16, 4)]

	return final


def matrix_to_bytes(matrix: 'list'):

	"""
	Converts a 4x4 matrix to a bytearray
	"""


	final = bytearray()
	for i in range(4):
		for j in range(4):
			final.append(matrix[i][j])

	return final


def gmul(a: 'int', b: 'int'):

	"""
	Multiplication in GF(2^8)
	"""

	product = 0

	for i in range(8):

		if(b & 0x1):
			product ^= a

		a_high_bit_set = a & 0x80

		a <<= 1

		if(a_high_bit_set):
			a ^= 0x11b

		b >>= 1

	return product


def multiply_matrix(a, b):

	"""
	Multiplies 2 matrices in GF(2^8)
	"""

	m1 = len(a)
	n1 = len(a[0])

	m2 = len(b)
	n2 = len(b[0])

	c = [[0 for j in range(n2)] for i in range(m1)]

	for i in range(m1):
		for j in range(n2):
			temp = 0
			for k in range(n1):
				temp ^= gmul(a[i][k], b[k][j])
			c[i][j] = temp


	return c


def print_mat(matrix: 'list[int][int]') -> None:

	for i in range(len(matrix)):
		for j in range(len(matrix[0])):
			print(f"{(matrix[i][j]) :02x}", end = " ")
		print()

	print()


def lrotate(matrix, row, by=1):

	rotations = by % len(matrix[0])

	return matrix[row][by:] + matrix[row][:by]


def rrotate(matrix, row, by=1):

	rotations = by % len(matrix[0])

	return matrix[row][len(matrix[0]) - rotations:] + matrix[row][0 : len(matrix[0]) - rotations]


def shift_rows(state: 'list[int][int]') -> None:
	state[1] = lrotate(state, 1, 1)
	state[2] = lrotate(state, 2, 2)
	state[3] = lrotate(state, 3, 3)


def inv_shift_rows(state: 'list[int][int]') -> None:
	state[1] = rrotate(state, 1, 1)
	state[2] = rrotate(state, 2, 2)
	state[3] = rrotate(state, 3, 3)


def mix_columns(state: 'list[int][int]') -> None:

	a = [
		[0x02, 0x03, 0x01, 0x01],
		[0x01, 0x02, 0x03, 0x01],
		[0x01, 0x01, 0x02, 0x03],
		[0x03, 0x01, 0x01, 0x02]
	]


	state[::] = multiply_matrix(a, state)


def inv_mix_columns(state: 'list[int][int]') -> None:

	a = [
		[0x0e, 0x0b, 0x0d, 0x09],
		[0x09, 0x0e, 0x0b, 0x0d],
		[0x0d, 0x09, 0x0e, 0x0b],
		[0x0b, 0x0d, 0x09, 0x0e]
	]

	state[::] = multiply_matrix(a, state)


def sub_bytes(state: 'list[int][int]') -> None:

	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] = s_box[state[i][j]]


def inv_sub_bytes(state: 'list[int][int]') -> None:

	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] = inv_s_box[state[i][j]]


def add_round_key(state, round_key):

	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] ^= round_key[i][j]


def aes_round(state, round_key):

	sub_bytes(state)
	shift_rows(state)
	mix_columns(state)
	add_round_key(state, round_key)


def inv_aes_round(state, round_key):

	add_round_key(state, round_key)
	inv_mix_columns(state)
	inv_shift_rows(state)
	inv_sub_bytes(state)


def sub_word(word: 'list[int]') -> 'list[int]':

	return [s_box[i] for i in word]


def rotate_word(word: 'list[int]') -> 'list[int]':
	return word[1:] + word[:1]


def xor_arrays(a: 'list[int]', b: 'list[int]') -> 'list[int]':
	return [i ^ j for i, j in zip(a, b)]


def change_order(state: 'list[int][int]', from_: 'str', to_: 'str') -> 'list[int][int]':

	# temp = [[ele for ele in row] for row in state]

	# for i in range(len(state)):
	# 	for j in range(len(state[0])):

	if(from_ == "row-major" and to_ == "col-major"):
		return transpose(state)

	if(from_ == "col-major" and to_ == "row-major"):
		return transpose(state)


def pad(data: 'bytes') -> 'bytes':

	padding_len = 16 - (len(data) % 16)
	padding = bytes([padding_len] * padding_len)
	return data + padding


def unpad(data: 'bytes') -> 'bytes':

	padding_len = data[-1]
	unpadded = data[ : -padding_len]
	return unpadded


def split_into_blocks(data: 'bytes', block_size=16):

	if(len(data) % 16 != 0):
		raise Exception("Length of data not a multiple of 16")

	return [data[i : i+16] for i in range(0, len(data), 16)]


def test_key_expansion(key_size):

	if(key_size == 128):
		key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
		return key


	elif(key_size == 192):
		key = b"\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"
		return key


	elif(key_size == 256):
		key = b"\60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"
		return key


	else:

		exit(0)


def test_algorithm(key_size):

	if(key_size == 128):
		data = b"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34"
		key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"			# 128 bit key
		return key, data


	elif(key_size == 192):
		data = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
		key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"		# 192 bit key
		return key, data


	elif(key_size == 256):
		data = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
		key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"		# 256 bit key
		return key, data


	else:

		exit(0)


def xor_bytes(a: 'bytes', b: 'bytes'):

	return bytes(i ^ j for i, j in zip(a, b))





class AES:

	rounds_wrt_key_size = {16 : 10, 24 : 12, 32 : 14}

	def __init__(self, master_key: 'bytes') -> None:

		self.master_key = master_key

		self.Nr = AES.rounds_wrt_key_size[len(self.master_key)]
		self.Nb = 4

		if(self.Nr == 10):
			self.Nk = 4


		elif(self.Nr == 12):
			self.Nk = 6


		elif(self.Nr == 14):
			self.Nk = 8




		self.round_keys = self.expand_key(self.master_key)


	def expand_key(self, key: 'list[int]') -> 'list[int][int]':

		words = []

		i = 0

		while(i < self.Nk):


			val = [key[(i*4)+0], key[(i*4)+1], key[(i*4)+2], key[(i*4)+3]]



			words.append(val)
			i += 1

		i = self.Nk

		while(i < self.Nb*(self.Nr + 1)):
			temp = words[i - 1]

			if(i % self.Nk == 0):

				temp = xor_arrays(sub_word(rotate_word(temp)), [rcon[i // self.Nk], 0, 0, 0])

			elif(self.Nk > 6 and i%self.Nk == 4):
				temp = sub_word(temp)

			words.append(xor_arrays(words[i - self.Nk], temp))

			i += 1

		return words


	def encrypt_block(self, data: 'bytes') -> 'bytes':

		block = bytes_to_matrix(data)

		state = [[ele for ele in row] for row in block]

		state = change_order(state, "row-major", "col-major")




		add_round_key(state, transpose(self.round_keys[0 : self.Nb]))


		for i in range(1, self.Nr):
			# print(f"At start of round {i}")



			sub_bytes(state)
			shift_rows(state)
			mix_columns(state)
			add_round_key(state, transpose(self.round_keys[i*self.Nb : (i+1)*self.Nb]))

			# aes_round(state, transpose(self.round_keys[i*self.Nk : (i+1)*self.Nb]))

		sub_bytes(state)
		shift_rows(state)
		add_round_key(state, transpose(self.round_keys[self.Nr*self.Nb : (self.Nr+1)*self.Nb]))


		return matrix_to_bytes(change_order(state, "col-major", "row-major"))
		return state


	def decrypt_block(self, data: 'bytes') -> 'bytes':

		block = bytes_to_matrix(data)

		state = [[ele for ele in row] for row in block]
		state = change_order(state, "row-major", "col-major")

		add_round_key(state, transpose(self.round_keys[self.Nr*self.Nb : (self.Nr+1)*self.Nb]))

		for i in range(self.Nr-1, 0, -1):

			inv_shift_rows(state)
			inv_sub_bytes(state)
			add_round_key(state, transpose(self.round_keys[i*self.Nb : (i+1)*self.Nb]))
			inv_mix_columns(state)


		inv_sub_bytes(state)
		inv_shift_rows(state)
		add_round_key(state,transpose(self.round_keys[0 : self.Nb]))

		return matrix_to_bytes(change_order(state, "col-major", "row-major"))
		return state


	def encrypt_ecb(self, raw_data: 'bytes') -> 'bytes':

		raw_data = pad(raw_data)

		byte_blocks = split_into_blocks(raw_data)

		encrypted_byte_blocks = []

		for block in byte_blocks:

			encrypted_block = self.encrypt_block(block)
			encrypted_byte_blocks.append(encrypted_block)

		return b"".join([enc_block for enc_block in encrypted_byte_blocks])


	def decrypt_ecb(self, enc_data: 'bytes') -> 'bytes':

		enc_byte_blocks = split_into_blocks(enc_data)

		decrypted_byte_blocks = []

		for block in enc_byte_blocks:

			decrypted_block = self.decrypt_block(block)
			decrypted_byte_blocks.append(decrypted_block)


		return unpad(b"".join([dec_block for dec_block in decrypted_byte_blocks]))
	

	def encrypt_cbc(self, raw_data: 'bytes', iv: 'bytes'):


		raw_data = pad(raw_data)

		prev = iv

		byte_blocks = split_into_blocks(raw_data)

		encrypted_byte_blocks = []

		for block in byte_blocks:

			encrypted_block = self.encrypt_block(xor_bytes(block, prev))
			encrypted_byte_blocks.append(encrypted_block)
			prev = encrypted_block

		return b"".join([enc_block for enc_block in encrypted_byte_blocks])
		

	def decrypt_cbc(self, enc_data: 'bytes', iv: 'bytes'):

		prev = iv

		enc_byte_blocks = split_into_blocks(enc_data)

		decrypted_byte_blocks = []

		# for i in range(0, len(enc_byte_blocks)):

		for block in enc_byte_blocks:

			# byte_block = enc_byte_blocks[i]

			decrypted_block = xor_bytes(self.decrypt_block(block), prev)
			decrypted_byte_blocks.append(decrypted_block)

			prev = block

		
		return unpad(b"".join([dec_block for dec_block in decrypted_byte_blocks]))
	
	


if __name__ =="__main__":

	key_size = 256


	key = test_key_expansion(key_size)

	key, _ = test_algorithm(key_size)
	iv = os.urandom(16)

	AES_object = AES(key)

	original_data = os.urandom(10**3)

	encrypted =  AES_object.encrypt_cbc(original_data, iv)
	decrypted =  AES_object.decrypt_cbc(encrypted, iv)


	print(original_data == decrypted)


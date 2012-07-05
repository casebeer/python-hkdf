'''
HKDF - HMAC Key Derivation Function

http://tools.ietf.org/html/draft-krawczyk-hkdf-01

Step 1: Extract

PRK = HKDF-Extract(salt, IKM)

Options:
	Hash     a hash function; HashLen denotes the length of the
				hash function output in octets
Inputs:
	salt     optional salt value (a non-secret random value);
				if not provided, it is set to a string of HashLen zeros.
	IKM      input keying material
Output:
	PRK      a pseudo-random key (of HashLen octets)

The output PRK is calculated as follows:

PRK = HMAC-Hash(salt, IKM)

Step 2: Expand

OKM = HKDF-Expand(PRK, info, L)

Options:
	Hash     a hash function; HashLen denotes the length of the
				hash function output in octets
Inputs:
	PRK      a pseudo-random key of at least HashLen octets
				(usually, the output from the Extract step)
	info     optional context and application specific information
				(can be a zero-length string)
	L        length of output keying material in octets
				(<= 255*HashLen)
Output:
	OKM      output keying material (of L octets)

The output OKM is calculated as follows:

N = ceil(L/HashLen)
T = T(1) | T(2) | T(3) | ... | T(N)
OKM = first L octets of T

where:
T(0) = empty string (zero length)
T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
...

(where the constant concatenated to the end of each T(n) is a
single octet.)

'''

import hmac
import hashlib

def hkdf_extract(salt, input_key_material, hash=hashlib.sha512):
	'''
	Extract a pseudorandom key suitable for use with hkdf_expand 
	from the input_key_material and a salt using HMAC with the 
	provided hash (default SHA-512). 

	salt should be a random, application-specific byte string. If
	salt is None or the empty string, an all-zeros string of the same
	length as the hash's block size will be used instead per the RFC.
	
	See the HKDF draft RFC and paper for usage notes. 
	'''
	hash_len = hash().digest_size
	if salt == None or len(salt) == 0:
		salt = chr(0) * hash_len
	return hmac.new(salt, input_key_material, hash).digest()

def hkdf_expand(pseudo_random_key, info="", length=32, hash=hashlib.sha512):
	'''
	Expand `pseudo_random_key` and `info` into a key of length `bytes` using 
	HKDF's expand function based on HMAC with the provided hash (default 
	SHA-512). See the HKDF draft RFC and paper for usage notes. 
	'''
	hash_len = hash().digest_size
	length = int(length)
	if length > 255 * hash_len:
		raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" %\
			(hash_len, 255 * hash_len))
	blocks_needed = length / hash_len + (0 if length % hash_len == 0 else 1) # ceil
	okm = ""
	output_block = ""
	for counter in range(blocks_needed):
		output_block = hmac.new(pseudo_random_key, output_block + info + chr(counter + 1), hash).digest()
		okm += output_block
	return okm[:length]


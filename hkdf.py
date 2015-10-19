from __future__ import division

import hmac
import hashlib
import sys
from struct import pack, error as struct_error
from itertools import count, islice

if sys.version_info[0] == 3:
	buffer = lambda x: x


MAX_INT64 = 0xffffffffffffffffffffffffffffffff


def COUNTER8(x):
	return pack('>B', x)


def COUNTER16(x):
	return pack('>H', x)


def COUNTER32(x):
	return pack('>I', x)


def COUNTER64(x):
	return pack('>Q', x)


def COUNTER128(x):
	return pack('>QQ', (x >> 64) & MAX_INT64, x & MAX_INT64)


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
		salt = bytearray((0,) * hash_len)
	return hmac.new(bytes(salt), buffer(input_key_material), hash).digest()


def hkdf_generator(pseudo_random_key,
				   info=b"",
				   hash=hashlib.sha512,
				   counter=COUNTER8):
	'''
	Expand `pseudo_random_key` and `info` using HKDF's expand function based on
	HMAC with the provided hash (default SHA-512). An iterable is returned that
	returns blocks one by one.

	The `counter` argument may optionally be used to support more than
	255 blocks (e.g. for a 32bit counter use `hkdf.COUNTER32`).

	See the HKDF draft RFC and paper for usage notes.

	'''

	mac = hmac.new(pseudo_random_key, None, hash)
	output_block = b''

	try:
		for i in count(start=1):
			h = mac.copy()
			h.update(buffer(
				output_block
				+ info
				+ counter(i)))
			output_block = h.digest()

			yield output_block

	except struct_error:
		raise StopIteration('Last block reached')


def hkdf_expand(pseudo_random_key,
				info=b"",
				length=32,
				hash=hashlib.sha512,
				counter=COUNTER8):
	'''
	Expand `pseudo_random_key` and `info` into a key of length `bytes` using
	HKDF's expand function based on HMAC with the provided hash (default
	SHA-512).

	The `counter` argument may optionally be used to support more than
	255 blocks (e.g. for a 32bit counter use `hkdf.COUNTER32`).

	See the HKDF draft RFC and paper for usage notes.
	'''
	hash_len = hash().digest_size
	blocks_needed = length // hash_len + (0 if length % hash_len == 0 else 1)  # ceil

	try:
		# Check if count of the last block will be small enough to pack.
		counter(blocks_needed)
	except struct_error:
		raise ValueError("Need a counter with more bits to support the given length")

	generator = hkdf_generator(pseudo_random_key, info, hash, counter=counter)
	okm = b''.join(islice(generator, blocks_needed))[:length]

	return okm


class Hkdf(object):

	'''
	Wrapper class for HKDF extract and expand functions
	'''

	def __init__(self, salt, input_key_material, hash=hashlib.sha256):
		'''
		Extract a pseudorandom key from `salt` and `input_key_material` arguments.

		See the HKDF draft RFC for guidance on setting these values. The constructor
		optionally takes a `hash` arugment defining the hash function use,
		defaulting to hashlib.sha256.
		'''
		self._hash = hash
		self._prk = hkdf_extract(salt, input_key_material, self._hash)

	def expand(self, info=b"", length=32):
		'''
		Generate output key material based on an `info` value

		Arguments:
		- info - context to generate the OKM
		- length - length in bytes of the key to generate

		See the HKDF draft RFC for guidance.
		'''
		return hkdf_expand(self._prk, info, length, self._hash)

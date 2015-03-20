'''
HKDF - HMAC Key Derivation Function

This module implements the HMAC Key Derivation function, defined at

    http://tools.ietf.org/html/draft-krawczyk-hkdf-01

There are two interfaces: a functional interface, with separate extract
and expand functions as defined in the draft RFC, and a wrapper class for
these functions. 

## Functional interface

To use the functional interface, pass the pseudorandom key generated
by hmac_extract([salt], [input key material]) to hmac_expand(...).
`salt` should be a random, non-secret, site-specific string, but may be
set to None. See section 3.1 of the HKDF draft for more details. 

In addition to the PRK output by hmac_extract, hmac_expand takes an 
`info` argument, which permits generating multiple keys based on the 
same PRK, and a `length` argument, which defines the number of bytes 
of output key material to generate. `length` must be less than or equal 
to 255 time the block size, in bytes, of the hash function being used. 
See section 3.2 of the HKDF draft for more information on using the `info`
argument. 

The hash function to use can be specified for both hmac_extract and 
hmac_expand as the `hash` kw argument, and defaults to SHA-256 as implemented
by the hashlib module. It must be the same for both extracting and expanding.

Example:

    prk = hkdf_extract("8e94ef805b93e683ff18".decode("hex"), "asecretpassword")
    key = hkdf_expand(prk, "context1", 16)

## "Hkdf" wrapper class

To use the wrapper class, instantiate the Hkdf() class with a salt, input
key material, and optionally, a hash function. You may then call 
expand([info], [length]) on the Hkdf instance to generate output key 
material:

    kdf = Hkdf("8e94ef805b93e683ff18".decode("hex"), "asecretpassword")
    key = kdf.expand("context1", 16)

## HKDF-Extract and HKDF-Expand definitions from the draft RFC:

> Step 1: Extract
> 
> PRK = HKDF-Extract(salt, IKM)
> 
> Options:
> 	Hash     a hash function; HashLen denotes the length of the
> 				hash function output in octets
> Inputs:
> 	salt     optional salt value (a non-secret random value);
> 				if not provided, it is set to a string of HashLen zeros.
> 	IKM      input keying material
> Output:
> 	PRK      a pseudo-random key (of HashLen octets)
> 
> The output PRK is calculated as follows:
> 
> PRK = HMAC-Hash(salt, IKM)
> 
> Step 2: Expand
> 
> OKM = HKDF-Expand(PRK, info, L)
> 
> Options:
> 	Hash     a hash function; HashLen denotes the length of the
> 				hash function output in octets
> Inputs:
> 	PRK      a pseudo-random key of at least HashLen octets
> 				(usually, the output from the Extract step)
> 	info     optional context and application specific information
> 				(can be a zero-length string)
> 	L        length of output keying material in octets
> 				(<= 255*HashLen)
> Output:
> 	OKM      output keying material (of L octets)
> 
> The output OKM is calculated as follows:
> 
> N = ceil(L/HashLen)
> T = T(1) | T(2) | T(3) | ... | T(N)
> OKM = first L octets of T
> 
> where:
> T(0) = empty string (zero length)
> T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
> T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
> T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
> ...
> 
> (where the constant concatenated to the end of each T(n) is a
> single octet.)

'''
from __future__ import division

import hmac
import hashlib
import sys

if sys.version_info[0] == 3:
	buffer = lambda x: x

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

def hkdf_expand(pseudo_random_key, info=b"", length=32, hash=hashlib.sha512):
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
	blocks_needed = length // hash_len + (0 if length % hash_len == 0 else 1) # ceil
	okm = b""
	output_block = b""
	for counter in range(blocks_needed):
		output_block = hmac.new(pseudo_random_key, buffer(output_block + info + bytearray((counter + 1,))),\
			hash).digest()
		okm += output_block
	return okm[:length]

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


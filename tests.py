#
# Tests for hkdf.py. Run with Nose.
#

import hkdf
import hashlib
import UserDict

try:
	from nose.tools import assert_equals
except ImportError,e:
	def assert_equals(a, b):
		'''
		Assert a and b are equal. 
		
		Assume a and b are raw binary data and escape before printing.
		'''
		try:
			assert a == b
		except AssertionError:
			print "AssertionError: {a} != {b}".format(a=a.encode("hex"), b=b.encode("hex"))
			raise

class TestCase(UserDict.IterableUserDict):
	'''Pretty print test cases'''
	def __str__(self):
		if (self["salt"] == None):
			print_salt = "None"
		elif(len(self["salt"]) <= 4):
			print_salt = '"' + self["salt"].encode("hex")[:8] + '"'
		else:
			print_salt = '"' + self["salt"].encode("hex")[:8] + '..."'

		return """{name} (IKM="{ikm_start}", salt={salt_start})""".format(
			name=self.get("name", "Unnamed test case"),
			ikm_start=self["IKM"].encode("hex")[:8] + \
				"..." if len(self["IKM"]) > 4 else "",
			salt_start=print_salt,
			)
	__repr__ = __str__

#### HKDF test vectors from draft RFC

test_vectors = {}

# A.1.  Test Case 1
# Basic test tv_number with SHA-256

test_vectors[1] = TestCase({
	"name": "A.1 Test Case 1",
	"hash": hashlib.sha256,
	"IKM"   : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex"),
	"salt"  : "000102030405060708090a0b0c".decode("hex"),
	"info"  : "f0f1f2f3f4f5f6f7f8f9".decode("hex"),
	"L"     : 42,
	"PRK"   : "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".decode("hex"),
	"OKM"   : "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".decode("hex")
})

# A.2.  Test Case 2
# Test with SHA-256 and longer inputs/outputs

test_vectors[2] = TestCase({
	"name"  : "A.2 Test Case 2",
	"hash"  : hashlib.sha256,
	"IKM"   : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".decode("hex"),
	"salt"  : "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".decode("hex"),
	"info"  : "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".decode("hex"),
	"L"     : 82,
	"PRK"   : "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244".decode("hex"),
	"OKM"   : "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".decode("hex")
})


# A.3.  Test Case 3
# Test with SHA-256 and zero-length salt/info

test_vectors[3] = TestCase({
	"name" : "A.3 Test Case 3",
	"hash" : hashlib.sha256,
	"IKM"  : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex"),
	"salt" : "",
	"info" : "",
	"L"    : 42,
	"PRK"  : "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04".decode("hex"),
	"OKM"  : "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".decode("hex")
})

# A.4.  Test Case 4
# Basic test tv_number with SHA-1

test_vectors[4] = TestCase({
	"name"  : "A.4 Test Case 4",
	"hash"  : hashlib.sha1,
	"IKM"   : "0b0b0b0b0b0b0b0b0b0b0b".decode("hex"),
	"salt"  : "000102030405060708090a0b0c".decode("hex"),
	"info"  : "f0f1f2f3f4f5f6f7f8f9".decode("hex"),
	"L"     : 42,
	"PRK"   : "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243".decode("hex"),
	"OKM"   : "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896".decode("hex")
})

# A.5.  Test Case 5
# Test with SHA-1 and longer inputs/outputs

test_vectors[5] = TestCase({
	"name"  : "A.5 Test Case 5",
	"hash"  : hashlib.sha1,
	"IKM"   : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".decode("hex"),
	"salt"  : "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".decode("hex"),
	"info"  : "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".decode("hex"),
	"L"     : 82,
	"PRK"   : "8adae09a2a307059478d309b26c4115a224cfaf6".decode("hex"),
	"OKM"   : "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4".decode("hex")
})

# A.6.  Test Case 6
# Test with SHA-1 and zero-length salt/info

test_vectors[6] = TestCase({
	"name"  : "A.6 Test Case 6",
	"hash"  : hashlib.sha1,
	"IKM"   : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode("hex"),
	"salt"  : "",
	"info"  : "",
	"L"     : 42,
	"PRK"   : "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01".decode("hex"),
	"OKM"   : "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918".decode("hex")
})

#### test helpers

def tv_extract(tv_number):
	tv = test_vectors[tv_number]
	return hkdf.hkdf_extract(tv["salt"], tv["IKM"], tv["hash"])

def tv_expand(tv_number):
	tv = test_vectors[tv_number]
	test_prk = hkdf.hkdf_extract(tv["salt"], tv["IKM"], tv["hash"])
	return hkdf.hkdf_expand(test_prk, tv["info"], tv["L"], tv["hash"])

#### Nose test functions

def test_functional_interface():
	for tv in test_vectors.values():
		yield check_fun_tv, tv

def test_wrapper_class():
	for tv in test_vectors.values():
		yield check_class_tv, tv

def check_fun_tv(tv):
	'''
	Generate and check HKDF pseudorandom key and output key material for a specific test vector
	
	PRK = HKDF-Extract([test vector values])
	OKM = HKDF-Expand(PRK, [test vector values])
	'''

	test_prk = hkdf.hkdf_extract(tv["salt"], tv["IKM"], tv["hash"])
	test_okm = hkdf.hkdf_expand(test_prk, tv["info"], tv["L"], tv["hash"])
	print "%s" % tv
	print "PRK: %s" % ("match" if test_prk == tv["PRK"] else "FAIL")
	print "OKM: %s" % ("match" if test_okm == tv["OKM"] else "FAIL")
	print

	assert_equals(test_prk, tv["PRK"])
	assert_equals(test_okm, tv["OKM"])

def check_class_tv(tv):
	'''Test HKDF output via wrapper class'''

	kdf = hkdf.Hkdf(tv["salt"], tv["IKM"], tv["hash"])
	test_okm = kdf.expand(tv["info"], tv["L"])

	print "%s (via wrapper class)" % tv
	print "PRK: %s" % ("match" if kdf._prk == tv["PRK"] else "FAIL")
	print "OKM: %s" % ("match" if test_okm == tv["OKM"] else "FAIL")
	print

	assert_equals(kdf._prk, tv["PRK"])
	assert_equals(test_okm, tv["OKM"])

if __name__ == "__main__":
	for f, tv in test_functional_interface():
		f(tv)
	for f, tv in test_wrapper_class():
		f(tv)

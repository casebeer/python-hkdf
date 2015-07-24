HKDF - HMAC Key Derivation Function
===================================

This module implements the HMAC Key Derivation function, defined at

    http://tools.ietf.org/html/draft-krawczyk-hkdf-01

There are two interfaces: a functional interface, with separate extract
and expand functions as defined in the draft RFC, and a wrapper class for
these functions.

Functional interface
--------------------

To use the functional interface, pass the pseudorandom key generated
by ``hmac_extract([salt], [input key material])`` to ``hmac_expand(...)``.
``salt`` should be a random, non-secret, site-specific string, but may be
set to None. See section 3.1 of the HKDF draft for more details.

In addition to the PRK output by ``hmac_extract()``, ``hmac_expand()`` takes an
``info`` argument, which permits generating multiple keys based on the
same PRK, and a ``length`` argument, which defines the number of bytes
of output key material to generate. ``length`` must be less than or equal
to 255 time the block size, in bytes, of the hash function being used.
See section 3.2 of the HKDF draft for more information on using the ``info``
argument.

The hash function to use can be specified for both ``hmac_extract()`` and
``hmac_expand()`` as the ``hash`` kw argument, and **defaults to SHA-512** as implemented
by the hashlib module. It must be the same for both extracting and expanding.

Example::

    from binascii import unhexlify
    prk = hkdf_extract(unhexlify(b"8e94ef805b93e683ff18"), b"asecretpassword")
    key = hkdf_expand(prk, b"context1", 16)

``Hkdf`` wrapper class
----------------------

To use the wrapper class, instantiate the ``Hkdf()`` class with a salt, input
key material, and optionally, a hash function. Note that **the default hash function
for the wrapper class is SHA-256**, which differs from the default for the functional
interface. You may then call ``expand([info], [length])`` on the Hkdf instance to 
generate output key material::

    kdf = Hkdf(unhexlify(b"8e94ef805b93e683ff18"), b"asecretpassword", hash=hashlib.sha512)
    key = kdf.expand(b"context1", 16)

Changelog
---------

- 0.0.3 – Move documentation from module docstring to README.rst
- 0.0.2 – Python 3.3, 3.4 support
- 0.0.1 – Initial release

Please report any bugs at

    https://www.github.com/casebeer/python-hkdf



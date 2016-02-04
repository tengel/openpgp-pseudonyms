__copyright__ = """
Copyright (C) Timo Engel (timo-e@freenet.de), Berlin 2012.
This program was written as part of a master thesis advised by 
Prof. Dr. Ruediger Weis at the Beuth University of Applied 
Sciences Berlin.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import Crypto.PublicKey.RSA
import Crypto.Cipher.CAST
import Crypto.Cipher.DES3
import Crypto.Cipher.Blowfish
import Crypto.Cipher.AES
import math
import hashlib

# ------------------------------------------------------------------------------

HASH_MD5    = 1
HASH_SHA1   = 2 
HASH_RIPEMD = 3 
HASH_SHA256 = 8 
HASH_SHA384 = 9 
HASH_SHA512 = 10
HASH_SHA224 = 11

HASH_SIZE = {HASH_MD5:    128,
             HASH_SHA1:   160,
             HASH_RIPEMD: 160,
             HASH_SHA256: 256,
             HASH_SHA384: 384, 
             HASH_SHA512: 512,
             HASH_SHA224: 224}

# ------------------------------------------------------------------------------

SYMALGORITHM_PLAIN    = 0
SYMALGORITHM_IDEA     = 1
SYMALGORITHM_3DES     = 2
SYMALGORITHM_CAST5    = 3
SYMALGORITHM_BLOWFISH = 4
SYMALGORITHM_AES128   = 7
SYMALGORITHM_AES192   = 8
SYMALGORITHM_AES256   = 9
SYMALGORITHM_TWOFISH  = 10

SYMALGORITHM_KEYSIZE = {SYMALGORITHM_PLAIN:    0,
                        SYMALGORITHM_IDEA:     16,
                        SYMALGORITHM_3DES:     24,
                        SYMALGORITHM_CAST5:    16,
                        SYMALGORITHM_BLOWFISH: 16,
                        SYMALGORITHM_AES128:   16,
                        SYMALGORITHM_AES192:   24,
                        SYMALGORITHM_AES256:   32,
                        SYMALGORITHM_TWOFISH:  32}

SYMALGORITHM_BLOCKSIZE = {SYMALGORITHM_PLAIN:    0,
                          SYMALGORITHM_IDEA:     8,
                          SYMALGORITHM_3DES:     8,
                          SYMALGORITHM_CAST5:    8,
                          SYMALGORITHM_BLOWFISH: 8,
                          SYMALGORITHM_AES128:   16,
                          SYMALGORITHM_AES192:   16,
                          SYMALGORITHM_AES256:   16,
                          SYMALGORITHM_TWOFISH:  0}

# ------------------------------------------------------------------------------

def i2b(i, octets=0):
    """
    Convert an integer to a string of bytes with the given number of octets..
    """
    b = []
    value = i
    while True:
        b.append(chr(value % 256))
        value /= 256
        if octets != 0:
            octets -= 1
        if value == 0 and octets == 0:
            break
    b.reverse()
    return ''.join(b)

# ------------------------------------------------------------------------------

def b2i(b):
    """
    Convert an string of bytes to an integer.
    """
    value = 0
    lenb = len(b)
    for i in range(0, lenb):
        shift = (lenb - i - 1) * 8
        value += ord(b[i]) << shift
    return value

# ------------------------------------------------------------------------------

def hash_md5(m):
    return hashlib.md5(m).digest()

# ------------------------------------------------------------------------------

def hash_sha1(m):
    return hashlib.sha1(m).digest()

# ------------------------------------------------------------------------------

def hash_sha256(m):
    return hashlib.sha256(m).digest()
    
# ------------------------------------------------------------------------------

def hash_sha384(m):
    return hashlib.sha384(m).digest()

# ------------------------------------------------------------------------------

def hash_sha512(m):
    return hashlib.sha512(m).digest()

# ------------------------------------------------------------------------------

def hash_sha224(m):
    return hashlib.sha224(m).digest()

# ------------------------------------------------------------------------------

def hash(data, algorithm):
    if algorithm == HASH_MD5:
        return hash_md5(data)
    elif algorithm == HASH_SHA1:
        return hash_sha1(data)
    elif algorithm == HASH_RIPEMD:
        raise Exception('not implemented')
    elif algorithm == HASH_SHA256:
        return hash_sha256(data)
    elif algorithm == HASH_SHA384:
        return hash_sha384(data)
    elif algorithm == HASH_SHA512:
        return hash_sha512(data)
    elif algorithm == HASH_SHA224:
        return hash_sha224(data)
    else:
        raise Exception('invalid hash algorithm')

# ------------------------------------------------------------------------------

def rsaBlind(m, r, e, n):
    return m * pow(r, e, n)

# ------------------------------------------------------------------------------

def rsaUnblind(r, n, s):
    return modInverse(r, n) * s % n

# ------------------------------------------------------------------------------

def rsaSign(m, d, n):
    return pow(m, d, n)

# ------------------------------------------------------------------------------

def rsaVerify(sig, m, e, n):
    return pow(sig, e, n) == m

# ------------------------------------------------------------------------------

def rsaEncrypt(m, e, n):
    return pow(m, e, n)

# ------------------------------------------------------------------------------

def rsaDecrypt(m, d, n):
    return pow(m, d, n)

# ------------------------------------------------------------------------------

def rsaGenerate(bits):
    """
    returns n, e, d, p, q, u
    """
    key = Crypto.PublicKey.RSA.generate(bits, randomBytes)
    return (key.n, key.e, key.d, key.p, key.q, key.u)

# ------------------------------------------------------------------------------

def gcd(a, b):
    """
    Use the euclidian algorithm to compute the greatest common divisor of two
    integers != 0.
    """
    while b != 0:
        a, b = b, a % b
    return a

# ------------------------------------------------------------------------------

def extEuclid(u, v):
    """
    The extended euclidean algorithm.
    return (u', v', gcd)
    """
    u2, u3 = 0, u
    v2, v3 = 1, v
    q = 0
    while v3 != 0:
        q = u3 / v3
        v2, u2 = u2 - v2 * q, v2
        v3, u3 = u3 - v3 * q, v3
    return (u3 - v * u2) / u, u2, u3 

# ------------------------------------------------------------------------------

def modInverse(u, v):
    """
    The inverse of u modulo v is calculated using the extended euclidean
    algorithm.
    return u^-1 mod v
    """
    u1, u3 = 1, u
    v1, v3 = 0, v
    while v3 != 0:
        q = u3 / v3
        v1, u1 = u1 - v1 * q, v1
        v3, u3 = u3 - v3 * q, v3
    if u3 != 1:
        raise Exception('no inverse')
    if u1 < 0:
        u1 += v
    return u1

# ------------------------------------------------------------------------------

def randomBytes(n):
    r = open('/dev/urandom', 'rb')
    b = r.read(n)
    r.close()
    return b

# ------------------------------------------------------------------------------

def randomInt(max):
    """
    Returns an random integer between 0 and max.
    """
    bytes = int(math.ceil(math.ceil(math.log(max + 1, 2)) / 8))
    return b2i(randomBytes(bytes)) % max + 1

# ------------------------------------------------------------------------------

def symEncrypt(key, plaintext, algorithm):
    if algorithm == SYMALGORITHM_PLAIN:
        return plaintext
    elif algorithm == SYMALGORITHM_IDEA:
        raise Exception('not implemented')
    elif algorithm == SYMALGORITHM_3DES:
        cipher = Crypto.Cipher.DES3.new(key)
    elif algorithm == SYMALGORITHM_CAST5:
        cipher = Crypto.Cipher.CAST.new(key, Crypto.Cipher.CAST.MODE_ECB)
    elif algorithm ==  SYMALGORITHM_BLOWFISH:
        cipher = Crypto.Cipher.Blowfish.new(key)
    elif algorithm == SYMALGORITHM_AES128:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    elif algorithm == SYMALGORITHM_AES192:
        cipher = Crypto.Cipher.AES.new(key)
    elif algorithm == SYMALGORITHM_AES256:
        cipher = Crypto.Cipher.AES.new(key)
    elif algorithm == SYMALGORITHM_TWOFISH:
        raise Exception('not implemented')
    else:
        raise Exception('unknown symmetric algorithm')
    return cipher.encrypt(plaintext)

# ------------------------------------------------------------------------------

def symDecrypt(key, ciphertext, algorithm):
    if algorithm == SYMALGORITHM_PLAIN:
        return ciphertext
    elif algorithm == SYMALGORITHM_IDEA:
        raise Exception('not implemented')
    elif algorithm == SYMALGORITHM_3DES:
        cipher = Crypto.Cipher.DES3.new(key, Crypto.Cipher.DES3.MODE_ECB)
    elif algorithm == SYMALGORITHM_CAST5:
        cipher = Crypto.Cipher.CAST.new(key, Crypto.Cipher.CAST.MODE_ECB)
    elif algorithm ==  SYMALGORITHM_BLOWFISH:
        cipher = Crypto.Cipher.Blowfish.new(key)
    elif algorithm == SYMALGORITHM_AES128:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    elif algorithm == SYMALGORITHM_AES192:
        cipher = Crypto.Cipher.AES.new(key)
    elif algorithm == SYMALGORITHM_AES256:
        cipher = Crypto.Cipher.AES.new(key)
    elif algorithm == SYMALGORITHM_TWOFISH:
        raise Exception('not implemented')
    else:
        raise Exception('unknown symmetric algorithm')
    return cipher.decrypt(ciphertext)

# ------------------------------------------------------------------------------

def encryptCFB(key, plaintext, iv, algorithm):
    blocksize = SYMALGORITHM_BLOCKSIZE[algorithm]
    fr = iv
    block = 0
    out = ''
    while block * blocksize < len(plaintext):
        fre = symEncrypt(key, fr, algorithm)
        if (block * blocksize) + blocksize > len(plaintext):
            size = len(plaintext) - (block * blocksize)
        else:
            size = blocksize
        fr = ''
        for i in range(0, size):
            fr += chr(ord(fre[i]) ^ ord(plaintext[(block * blocksize) + i]))
        block += 1
        out += fr
    return out

# ------------------------------------------------------------------------------

def decryptCFB(key, ciphertext, iv, algorithm):
    blocksize = SYMALGORITHM_BLOCKSIZE[algorithm]
    fr = iv
    block = 0
    out = ''
    while block * blocksize < len(ciphertext):
        fre = symEncrypt(key, fr, algorithm)
        if (block * blocksize) + blocksize > len(ciphertext):
            size = len(ciphertext) - (block * blocksize)
        else:
            size = blocksize
        fr = ciphertext[(block * blocksize):(block * blocksize) + size]
        for i in range(0, size):
            out += chr(ord(fre[i]) ^ ord(fr[i]))
        block += 1
    return out

# ------------------------------------------------------------------------------

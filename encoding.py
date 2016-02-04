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

import math

import crypto

# ------------------------------------------------------------------------------

ENCODING_PKCS15 = 1
ENCODING_ECASH = 2
ENCODING_PKCSPSS = 3

# ------------------------------------------------------------------------------

HASH_PREFIX = {crypto.HASH_MD5:   '\x30\x20\x30\x0C\x06\x08\x2A\x86\x48\x86\xF7'
                                  '\x0D\x02\x05\x05\x00\x04\x10',
               crypto.HASH_SHA1:  '\x30\x21\x30\x09\x06\x05\x2b\x0E\x03\x02\x1A'
                                  '\x05\x00\x04\x14',
               crypto.HASH_RIPEMD:'\x30\x21\x30\x09\x06\x05\x2B\x24\x03\x02\x01'
                                  '\x05\x00\x04\x14',
               crypto.HASH_SHA256:'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65'
                                  '\x03\x04\x02\x01\x05\x00\x04\x20',
               crypto.HASH_SHA384:'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65'
                                  '\x03\x04\x02\x02\x05\x00\x04\x30',
               crypto.HASH_SHA512:'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65'
                                  '\x03\x04\x02\x03\x05\x00\x04\x40',
               crypto.HASH_SHA224:'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65'
                                  '\x03\x04\x02\x04\x05\x00\x04\x1C'}

# ------------------------------------------------------------------------------

def pkcs15(pHash, emBits, algorithm):
    """
    Encode a hash using EMSA-PKCS1-v1_5.

    @param pHash: The hash over the message M to encode.
    @param emBits: Desired number of bits.
    @param algorithm: Hash algorithm.
    """
    T = (HASH_PREFIX[algorithm] + pHash)
    tLen = len(T)
    if emBits / 8 < tLen + 11:
        raise Exception('intended encoded message length too short')
    PS = '\xff' * (emBits / 8 - tLen - 3)
    EM = '\x00' + '\x01' + PS + '\x00' + T
    return EM

# ------------------------------------------------------------------------------

def ecash(data, emBits, algorithm):
    """
    Implementation of the ecash encoding scheme for signatures.
    H = f(x) = x_t || ... || x_1 || x_0
    x_0 = x
    x_i = H(x_0 || ... || x_(i-1))

    @param data: string to encode
    @param emBits: Number of bits of output.
    """

    t = ((emBits - len(data) * 8)) / crypto.HASH_SIZE[algorithm]
    xList = [data]
    for xi in range(1, t + 1):
        x_i = crypto.hash(''.join(xList), algorithm)
        xList.append(x_i)    
    return ''.join(xList)

# ------------------------------------------------------------------------------

def pssMGF(mgfSeed, maskLen, algorithm):
    """
    MGF1 Mask Generation Function.

    @param mgfSeed: The seed from which the bitmask is generated from.
    @param maskLen: Number of bytes in output.
    """
    hLen = crypto.HASH_SIZE[algorithm] / 8
    T = ""
    for counter in range(0, int(math.ceil(maskLen / float(hLen)))) :
        C = crypto.i2b(counter, 4)
        T = T + crypto.hash(mgfSeed + C, algorithm)
    return T[0:maskLen]

# ------------------------------------------------------------------------------

def pssEncode(M, sLen, emBits, algorithm):
    """
    Encoding for RSASSA-PSS signature scheme.
    
    @param M: Message to encode
    @param sLen: Numer of bytes for salt
    @param emBits: Number of bits of output, maximum 8*hLen + 8*sLen + 9
    @param algorithm: Hash algorithm to use.
    """
    if len(M) > 2**61 - 1:                                            # 1.
        raise Exception('message too long')
    mHash = crypto.hash(M, algorithm)                                 # 2.
    hLen = crypto.HASH_SIZE[algorithm] / 8
    emLen = int(math.ceil(emBits / 8.0))                              # 3.
    if emLen < hLen + sLen + 2:
        raise Exception('encoding error')
    salt = crypto.randomBytes(sLen)                                   # 4.
    M_ = '\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt            # 5.
    H = crypto.hash(M_, algorithm)                                    # 6.
    PS = (emLen - sLen - hLen - 2) * '\x00'                           # 7.
    DB = PS + '\x01' + salt                                           # 8.
    dbMask = pssMGF(H, emLen - hLen - 1, algorithm)                   # 9.
    maskedDBList = []                                                 # 10.
    for i in range(0, len(dbMask)):
        maskedDBList.append(chr(ord(DB[i]) ^ ord(dbMask[i])))
    bits = 8 * emLen - emBits                                         # 11.
    maskedDBList[0] = chr(ord(maskedDBList[0]) & 0xff >> bits)
    maskedDB = ''.join(maskedDBList)
    EM = maskedDB + H + '\xbc'                                        # 12.
    return EM

# ------------------------------------------------------------------------------

def pssVerify(M, EM, sLen, emBits, algorithm):
    """
    Verify an RSASSA-PSS encoded signature.

    @param M: Message to verify.
    @param EM: Signature to check.
    @param sLen: Number of bytes for salt
    @param emBits: Number of bits in signature (in EM)
    @param algorithm: Hash algorithm to use.
    """
    hLen = crypto.HASH_SIZE[algorithm] / 8
    if len(M) > 2**61 - 1:                                            # 1.
        raise Exception('message too long')
    mHash = crypto.hash(M, algorithm)                                 # 2.
    emLen = int(math.ceil(emBits / 8.0))                              # 3.
    if emLen < hLen + sLen + 2:
        raise Exception('inconsistant')
    if ord(EM[emLen - 1]) is not 0xbc:                                # 4.
        raise Exception('inconsistant')
    maskedDB = EM[0:emLen - hLen - 1]                                 # 5.
    H = EM[emLen - hLen - 1: emLen - 1]
    bits = 8 * emLen - emBits                                         # 6.
    if (~(0xff >> bits)) & ord(maskedDB[0]) != 0:
        raise Exception('inconsistant')
    dbMask = pssMGF(H, emLen - hLen - 1, algorithm)                   # 7.
    DBList = []                                                       # 8.
    for i in range(0, emLen - hLen - 1):
        DBList.append(chr(ord(maskedDB[i]) ^ ord(dbMask[i])))
    bits = 8 * emLen - emBits                                         # 9.
    DBList[0] = chr(ord(DBList[0]) & 0xff >> bits)
    DB = ''.join(DBList)
    for i in range(0, emLen - hLen - sLen - 2):                       # 10.
        if DB[i] != '\x00':
            raise Exception('inconsistant')
    if DB[emLen - hLen - sLen - 2] != '\x01':
        raise Exception('inconsistant')
    salt = DB[emLen - hLen - sLen - 1:emLen - hLen]                   # 11.
    M_ = '\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt            # 12.
    H_ = crypto.hash(M_, algorithm)                                   # 13.
    return H_ == H

# ------------------------------------------------------------------------------

def hashEncode(data, emBits, hashAlgorithm, encoding):
    """
    Create an encoded hashvalue with a given algorithm and encoding.
    
    @param data: The data to hash and encode.
    @param emBits: Desired number of bits in output.
    @param hashAlgorithm: The algorithm to use.
    @param encoding: The encoding scheme to use.
    """
    if encoding == ENCODING_PKCS15:
        return pkcs15(crypto.hash(data, hashAlgorithm), emBits, hashAlgorithm)
    elif encoding == ENCODING_ECASH:
        return ecash(data, emBits, hashAlgorithm)
    elif encoding == ENCODING_PKCSPSS:
        return pssEncode(data, crypto.HASH_SIZE[hashAlgorithm] / 8, emBits,
                             hashAlgorithm)
    else:
        raise Exception('invalid hash encoding')

# ------------------------------------------------------------------------------

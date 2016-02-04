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

from elements import *
from subpackets import *
import crypto
import encoding

ALGORITHM_RSA         = 1  # Encrypt or Sign
ALGORITHM_RSA_ENCRYPT = 2
ALGORITHM_RSA_SIGN    = 3
ALGORITHM_ELGAMAL     = 16
ALGORITHM_DSA         = 17

       
# ------------------------------------------------------------------------------

def algorithmToString(a):
    if a == ALGORITHM_RSA:
        s = 'RSA'
    elif a == ALGORITHM_RSA_ENCRYPT:
        s = 'RSA encrypt only'
    elif a == ALGORITHM_RSA_SIGN:
        s = 'RSA sign only'
    elif a == ALGORITHM_ELGAMAL:
        s = 'Elgamal'
    elif a == ALGORITHM_DSA:
        s = 'DSA'
    else:
        s = 'unknown'
    s += ' (%d)' % a
    return s

# ------------------------------------------------------------------------------

def symAlgorithmToString(a):
    if a == crypto.SYMALGORITHM_PLAIN:
        s = 'unencrypted'
    elif a == crypto.SYMALGORITHM_IDEA:
        s = 'IDEA'
    elif a == crypto.SYMALGORITHM_3DES:
        s = '3DES'
    elif a == crypto.SYMALGORITHM_CAST5:
        s = 'CAST5'
    elif a == crypto.SYMALGORITHM_BLOWFISH:
        s = 'Blowfish'
    elif a == crypto.SYMALGORITHM_AES128:
        s = 'AES 128'
    elif a == crypto.SYMALGORITHM_AES192:
        s = 'AES 192'
    elif a == crypto.SYMALGORITHM_AES256:
        s = 'AES 256'
    elif a == crypto.SYMALGORITHM_TWOFISH:
        s = 'Twofish'
    else:
        s = 'unknown'
    s += ' (%d)' % a
    return s

# ------------------------------------------------------------------------------

class Packet:
    """
    Base class for packets.
    """

    @classmethod
    def parse(self, stream, passphraseCallback=None):
        ptag = stream.read(1)
        if ptag == '':
            return None
        if ord(ptag) & 0x80 != 0x80:
            raise Exception('invalid packet header')
        if ord(ptag) & 0x40 == 0:
            # old format
            tag = (ord(ptag) & 0x3c) >> 2
            lengthType = ord(ptag) & 0x03
            if lengthType == 3:
                raise Exception('length type not implemented')
            lengthLen = 2 ** lengthType
            bodyLen = ScalarElement(stream.read(lengthLen)).value
        else:
            # new format
            tag = ord(ptag) & 0x3f
            bodyLen = ord(stream.read(1))
            if bodyLen < 192:
                pass
            elif bodyLen >= 192 and bodyLen <= 223:
                bodyLen = ((bodyLen - 192) << 8) + ord(stream.read(1)) + 192
            elif bodyLen == 255:
                 bodyLen = ScalarElement(stream.read(4)).value
            else:
                raise Exception('length type not implemented')
        
        if tag == SignaturePacket.TAG:
            return SignaturePacket.fromData(stream)
        elif tag == SecretKeyPacket.TAG:
            return SecretKeyPacket(stream, bodyLen, passphraseCallback)
        elif tag == PublicKeyPacket.TAG:
            return PublicKeyPacket(stream)
        elif tag == UserIDPacket.TAG:
            return UserIDPacket(stream, bodyLen)
        elif tag == BlindMessagePacket.TAG:
            return BlindMessagePacket.fromData(stream)
        elif tag == BlindSignaturePacket.TAG:
            return BlindSignaturePacket.fromData(stream)
        elif tag == NymPacket.TAG:
            return NymPacket.fromData(stream)
        else:
            print 'WARNING: unsupported package tag: %d' % tag


    @classmethod
    def createHeader(self, tag, pLen):
        if tag > 63:
            raise Exception('invalid tag')

        if pLen > 0 and pLen < 192:
            length = chr(pLen)
        elif pLen >= 192 and pLen <= 8383:
            lenBytes = ScalarElement(pLen).rep(2)
            length = chr(ord(lenBytes[0]) + 192) + lenBytes[1]
        else:
            raise Exception('lenth type not implemented')
        ptag = chr(0xc0 | tag)
        return ptag + length

# ------------------------------------------------------------------------------

class SignaturePacket(Packet):
    """
    Signature Packet (Tag 2)
    """

    TAG = 2

    def __init__(self):
        self.hashedSubpackets = SignatureSubpackets()
        self.subpackets = SignatureSubpackets()
        self.version = ScalarElement(4)
        self.signatureType = ScalarElement(0)

    @classmethod
    def fromData(self, s):
        sig = SignaturePacket()
        sig.version = ScalarElement(s.read(1))
        sig.signatureType = ScalarElement(s.read(1))
        if sig.signatureType.value == 0x13:
            pass
        elif sig.signatureType.value == 0x00:
            pass
        else:
            raise Exception('not implemented')
        sig.pubAlgorithm = ScalarElement(s.read(1))
        sig.hashAlgorithm = ScalarElement(s.read(1))
        hashedSubpacketLen = ScalarElement(s.read(2))
        hashedSubpacketData = s.read(hashedSubpacketLen.value)
        sig.hashedSubpackets = SignatureSubpackets.fromData(hashedSubpacketData)
        subpacketDataLen = ScalarElement(s.read(2))
        subpacketData = s.read(subpacketDataLen.value)
        sig.subpackets = SignatureSubpackets.fromData(subpacketData)
        sig.hashLeftTwo = s.read(2)
        sig.sig = MPIElement(s)
        return sig

    def rep(self):
        data = (self.version.rep(1) +
                self.signatureType.rep(1) +
                self.pubAlgorithm.rep(1) +
                self.hashAlgorithm.rep(1) +
                self.hashedSubpackets.rep() +
                self.subpackets.rep() + 
                self.hashLeftTwo +
                self.sig.rep())
        return Packet.createHeader(self.TAG, len(data)) + data

    def hashdata(self):        
        hashdata = (self.version.rep(1) +
                    self.signatureType.rep(1) +
                    self.pubAlgorithm.rep(1) +
                    self.hashAlgorithm.rep(1) +
                    self.hashedSubpackets.rep())
        return hashdata + '\x04\xff' + ScalarElement(len(hashdata)).rep(4)

    def __str__(self):
        return ('Signature Packet (tag %d):\n'
                '    Version: %s\n'
                '    Signature type: %s\n'
                '    Public-key algorithm: %s\n'
                '    Hash algorithm: %s\n'
                '    Hashed subpackets:\n%s\n'
                '    Unhashed subpackets: \n%s\n'
                '    Hash left 2 bytes: 0x%s\n'
                '    RSA m**d mod n: %s\n') % (self.TAG,
                                               self.version,
                                               self.signatureType,
                                               algorithmToString(self.pubAlgorithm.value),
                                               hashToString(self.hashAlgorithm.value),
                                               self.hashedSubpackets,
                                               self.subpackets,
                                               self.hashLeftTwo.encode('hex'),
                                               self.sig)

# ------------------------------------------------------------------------------

class PublicKeyPacket(Packet):
    """
    Public-Key Packet (Tag 6)
    """

    TAG = 6

    def __init__(self, s = None):
        if s is None: return
        self.version = ScalarElement(s.read(1))
        self.created = TimeElement(s.read(4))
        self.algorithm = ScalarElement(s.read(1))
        self.n = MPIElement(s)
        self.e = MPIElement(s)

    @classmethod
    def fromParameter(self, n, e):
        p = PublicKeyPacket()
        p.version = ScalarElement(4)
        p.created = TimeElement.now()
        p.algorithm = ScalarElement(ALGORITHM_RSA)
        p.n = n
        p.e = e
        return p

    def rep(self):
        data = (self.version.rep(1) +
                self.created.rep() +
                self.algorithm.rep(1) +
                self.n.rep() +
                self.e.rep())
        return Packet.createHeader(self.TAG, len(data)) + data
        
    def hashdata(self):
        data = (self.version.rep(1) + self.created.rep() + self.algorithm.rep(1) +
                self.n.rep() + self.e.rep())
        return '\x99' + ScalarElement(len(data)).rep(2) + data

    def __str__(self):
        return ('Public Key Packet (tag %d):\n'
                '    Version: %s\n'
                '    Created: %s\n'
                '    Algorithm: %s\n'
                '    RSA n: %s\n'
                '    RSA e: %s\n') % (self.TAG,
                                      self.version,
                                      self.created,
                                      algorithmToString(self.algorithm.value),
                                      self.n,
                                      self.e)

    def fingerprint(self):
        return crypto.hash_sha1(self.hashdata())

    def keyID(self):
        return self.fingerprint()[-8:]

# ------------------------------------------------------------------------------
    
class SecretKeyPacket(PublicKeyPacket):
    """
    Secret-Key Packet (Tag 5)
    """

    TAG = 5
    
    def __init__(self, s=None, length=0, passphraseCallback=None):
        PublicKeyPacket.__init__(self, s)
        self.passphrase = None
        if s is None:
            return
        self.s2kUsage = ord(s.read(1))
        if self.s2kUsage == 255 or self.s2kUsage == 254:
            self.symAlgorithm = ord(s.read(1))
            self.s2k = S2KElement(s)
            self.iv = s.read(crypto.SYMALGORITHM_BLOCKSIZE[self.symAlgorithm])
            encrypted = s.read(length - s.tell() + 3)
            if passphraseCallback is None:
                raise Exception('encrypted key and no passphraseCallback')
            symkey = self.s2k.generateKey(passphraseCallback(), self.symAlgorithm)
            decrypted = io.BytesIO(crypto.decryptCFB(symkey,
                                                     encrypted,
                                                     self.iv,
                                                     self.symAlgorithm))
            self.d = MPIElement(decrypted)
            self.p = MPIElement(decrypted)
            self.q = MPIElement(decrypted)
            self.u = MPIElement(decrypted)
            if self.s2kUsage == 254:
                self.checksum = decrypted.read(20)
                if self.checksum != crypto.hash_sha1(decrypted.getvalue()[:-20]):
                    raise Exception('invalid passphrase')
            else:
                raise Exception('not implemented')
        elif self.s2kUsage == 0:
            self.d = MPIElement(s)
            self.p = MPIElement(s)
            self.q = MPIElement(s)
            self.u = MPIElement(s)
            self.checksum = s.read(2)
        else:            
            raise Exception('not implemented')

    @classmethod
    def fromParameter(self, n, e, d, p, q, u):
        key = SecretKeyPacket()
        key.version = ScalarElement(4)
        key.created = TimeElement.now()
        key.algorithm = ScalarElement(ALGORITHM_RSA)
        key.n = n
        key.e = e
        key.d = d
        key.p = p
        key.q = q
        key.u = u
        key.checksum = '\x00\x00'
        return key

    def rep(self, passphrase=None, algorithm=crypto.SYMALGORITHM_AES256):
        passphrase = self.passphrase
        keydata = self.d.rep() + self.p.rep() + self.q.rep() + self.u.rep()
        s2kPart = '\x00'
        if passphrase is not None and len(passphrase) > 0:
            iv = crypto.randomBytes(crypto.SYMALGORITHM_BLOCKSIZE[algorithm])
            s2k = S2KElement()
            s2kPart = '\xfe' + chr(algorithm) + s2k.rep() + iv
            keydata += crypto.hash_sha1(keydata)
            keydata = crypto.encryptCFB(s2k.generateKey(passphrase, algorithm),
                                        keydata, iv, algorithm)
        else:
            keydata += '\x00\x00'
        data = (self.version.rep(1) + self.created.rep() + self.algorithm.rep(1) +
                self.n.rep() + self.e.rep() + s2kPart + keydata)
        return Packet.createHeader(self.TAG, len(data)) + data

    def __str__(self):
        s2kdetails = ''
        if self.s2kUsage == 254 or self.s2kUsage == 255:
            s2kdetails += (('    Sym. algorithm: %s\n'
                            '    %s\n') %
                           (symAlgorithmToString(self.symAlgorithm),
                           self.s2k))
        if self.s2kUsage != 0:
            s2kdetails += '    IV: %s\n' % self.iv.encode('hex')
        return ('Secret Key Packet (tag %d):\n'
                '    Version: %s\n'
                '    Created: %s\n'
                '    Algorithm: %s\n'
                '    RSA n: %s\n'
                '    RSA e: %s\n'
                '    S2K usage: %s\n'
                '%s'
                '    RSA d: %s\n'
                '    RSA p: %s\n'
                '    RSA q: %s\n'
                '    RSA u: %s\n'
                '    Checksum: %s\n') % (self.TAG,
                                         self.version,
                                         self.created,
                                         algorithmToString(self.algorithm.value),
                                         self.n,
                                         self.e,
                                         self.s2kUsage,
                                         s2kdetails,
                                         self.d,
                                         self.p,
                                         self.q,
                                         self.u,
                                         self.checksum.encode('hex'))

# ------------------------------------------------------------------------------
    
class UserIDPacket(Packet):
    """
    User ID Packet (Tag 13)
    """

    TAG = 13

    def __init__(self, s, length):
        self.id = s.read(length)

    def __str__(self):
        return ('User ID Packet (tag %d):\n'
               '    id: %s\n') % (self.TAG, self.id)

    def hashdata(self):
        return '\xb4' + ScalarElement(len(self.id)).rep(4) + self.id

    def rep(self):
        return Packet.createHeader(self.TAG, len(self.id)) + self.id

# ------------------------------------------------------------------------------

class BlindMessagePacket(Packet):
    """
    A blinded message (Tag 60)
    This packet type is not part of RFC4880
    """

    TAG = 60

    @classmethod
    def fromData(self, s):
        p = BlindMessagePacket()
        p.m = MPIElement(s)
        return p

    def __init__(self):
        pass

    def __str__(self):
        return ('Blinded Message (tag %d):\n'
                '    m = %s\n') % (self.TAG, self.m)
    def rep(self):
        data = self.m.rep()
        return Packet.createHeader(self.TAG, len(data)) + data

# ------------------------------------------------------------------------------

class BlindSignaturePacket(Packet):
    """
    A blinded message (Tag 61)
    This packet type is not part of RFC4880
    """

    TAG = 61

    @classmethod
    def fromData(self, s):
        p = BlindSignaturePacket()
        p.s = MPIElement(s)
        return p
    
    def __init__(self):
        pass

    def __str__(self):
        return ('Blind Signature (tag %d):\n'
                '    s = %s\n') % (self.TAG, self.s)
        
    def rep(self):
        data = self.s.rep()
        return Packet.createHeader(self.TAG, len(data)) + data

# ------------------------------------------------------------------------------

class NymPacket(Packet):
    """
    A Pseudonym consisting of a username, a random number and a self signature
    over both.
    """

    TAG = 62

    @classmethod
    def fromData(self, s):
        nym = NymPacket()
        idLen = ScalarElement(s.read(1))
        nym.id = s.read(idLen.value)
        nym.n = MPIElement(s)
        nym.signature = MPIElement(s)
        return nym

    @classmethod
    def fromParameter(self, id, n):
        nym = NymPacket()
        nym.id = id
        nym.n = n
        nym.signature = MPIElement(0)
        return nym

    def __init__(self):
        self.id = ''
        self.n = MPIElement(0)
        self.signature = MPIElement(0)

    def __str__(self):
        return ('Nym Packet (tag %d)\n'
                '    id = %s\n'
                '    n = %s\n'
                '    signature = %s\n' % (self.TAG, self.id, self.n,
                                          self.signature))

    def hashdata(self):
        """
        Hash used for self signature.
        """
        return ScalarElement(len(self.id)).rep(1) + self.id + self.n.rep()
        
    def computeSignature(self, secretKeyMessage):
        """
        Compute self signature
        """        
        key = secretKeyMessage.packets[SecretKeyPacket.TAG]
        m = encoding.hashEncode(self.hashdata(),
                                key.n.bits() - 1,
                                crypto.HASH_SHA256, encoding.ENCODING_PKCSPSS)
        s = crypto.rsaSign(crypto.b2i(m), key.d.value, key.n.value)
        self.signature = MPIElement(s)

        
    def isValid(self, keyMessage):
        """
        Verify the self signature.
        """
        key = keyMessage.packets.get(PublicKeyPacket.TAG)
        if key is None:
            key = keyMessage.packets.get(SecretKeyPacket.TAG)
        if key is None:
            raise Exception('no key in message')
        em = crypto.i2b(crypto.rsaEncrypt(self.signature.value, key.e.value,
                                          key.n.value))
        return encoding.pssVerify(self.hashdata(), em,
                                  crypto.HASH_SIZE[crypto.HASH_SHA256] / 8,
                                  key.n.bits() - 1, crypto.HASH_SHA256)
    
    def rep(self):
        data = (ScalarElement(len(self.id)).rep(1) + self.id + self.n.rep() +
                self.signature.rep())
        return Packet.createHeader(self.TAG, len(data)) + data

    def hash(self, bits):
        """
        Hash used for blind signature of CA.
        """
        return encoding.hashEncode(self.rep(), bits, crypto.HASH_SHA256,
                                   encoding.ENCODING_PKCS15)

    def fingerprint(self):
        return crypto.hash_sha1(self.hashdata())

    def keyID(self):
        return self.fingerprint()[-8:]

    
# ------------------------------------------------------------------------------

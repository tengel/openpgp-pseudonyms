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

# ------------------------------------------------------------------------------

class SignatureSubpackets:
    """
    Contains all hashed or unhashed subpackets of a signature packet.
    """

    def __init__(self):
        self.packets = []

    @classmethod
    def fromData(self, d):
        subpackets = SignatureSubpackets()
        p = 0
        while p < len(d):
            if ord(d[p]) < 192:
                lengthOfLen = 1
                subpacketLen = ord(d[p])
            if ord(d[p]) >= 192 and ord(d[p]) < 255:
                lengthOfLen = 2
                subpacketLen =  (((ord(d[p]) - 192) << 8) +
                                 ord(d[p + 1]) + 192)
            if ord(d[p]) == 255:
                lengthOfLen = 5
                raise Exception('not implemented')
                #subpacketLen =  [four-octet scalar starting at 2nd_octet]
            p += lengthOfLen
            subType = ord(d[p])
            p += 1

            subBody = d[p : p + subpacketLen - 1]
            p += subpacketLen - 1

            if subType == CreationTimeSubpacket.TAG:
                subpacket = CreationTimeSubpacket(subBody)
            elif subType == KeyExpirationSubpacket.TAG:
                subpacket = KeyExpirationSubpacket(subBody)
            elif subType == SymmetricAlgorithmsSubpacket.TAG:
                subpacket = SymmetricAlgorithmsSubpacket(subBody)
            elif subType == IssuerSubpacket.TAG:
                subpacket = IssuerSubpacket(subBody)
            elif subType == HashAlgorithmsSubpacket.TAG:
                subpacket = HashAlgorithmsSubpacket(subBody)
            elif subType == CompressionAlgorithmsSubpacket.TAG:
                subpacket = CompressionAlgorithmsSubpacket(subBody)
            elif subType == ServerPreferencesSubpacket.TAG:
                 subpacket = ServerPreferencesSubpacket(subBody)
            elif subType == KeyFlagsSubpacket.TAG:
                 subpacket = KeyFlagsSubpacket(subBody)
            elif subType == FeaturesSubpacket.TAG:
                 subpacket = FeaturesSubpacket(subBody)
            else:
                print 'WARNING: subpacket type %d not implemented' % subType
            subpackets.add(subpacket)
        return subpackets

    def add(self, subpacket):
        self.packets.append(subpacket)
    
    def get(self, tag):
        for subpacket in self.packets:
            if subpacket.TAG == tag:
                return subpacket
        return None


    def rep(self):
        data = ''
        for p in self.packets:
            data += p.rep()
        return ScalarElement(len(data)).rep(2) + data

    def __str__(self):
        s = ''
        for p in self.packets:
            s += '        ' + p.__str__(8) + '\n'
        return s[:-1]

# ------------------------------------------------------------------------------

class SignatureSubpacket:
    """
    Base class for signature subpackets.
    """

    @classmethod
    def createHeader(self, subType, pLen):
        if pLen >= 192:
            raise Exception('not implemented')
        return chr(pLen) + chr(subType)

# ------------------------------------------------------------------------------

class CreationTimeSubpacket(SignatureSubpacket, TimeElement):
    """
    Signature Creation Time.
    The time the signature was made.
    """
    TAG = 2

    def __init__(self, d):
        TimeElement.__init__(self, d)

    def __str__(self, indent=0):
        return ('Signature creation time (tag %d): %s') % (self.TAG,
                                                           time.ctime(self.value))

    def rep(self):
        return (self.createHeader(self.TAG, TimeElement.LEN + 1) +
                TimeElement.rep(self))

# ------------------------------------------------------------------------------

class KeyExpirationSubpacket(SignatureSubpacket, ScalarElement):
    """
    Key Expiration Time
    """
    TAG = 9

    def __init__(self, d):
        ScalarElement.__init__(self, d)

    def __str__(self, indent=0):
        return ('key expiration time (%d):\n' +
                indent * ' ' + '    keyCreation + %s seconds') % (self.TAG, self.value)
    
    def rep(self):
        return self.createHeader(self.TAG, + 4 + 1) + ScalarElement.rep(self, 4)

# ------------------------------------------------------------------------------

class SymmetricAlgorithmsSubpacket(SignatureSubpacket):
    """
    Preferred Symmetric Algorithms
    """

    TAG = 11

    def __init__(self, d):
        self.d = d
        
    def __str__(self, indent=0):
        return 'preferred symmetric algorithms (tag %d): %s' % (self.TAG, self.d.encode('hex'))

    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------

class IssuerSubpacket(SignatureSubpacket):
    """
    Issuer key id
    """

    TAG = 16

    def __init__(self, d):
        self.keyid = KeyIDElement(d)

    def __str__(self, indent=0):
        return 'issuer (tag %d): %s' % (self.TAG, self.keyid)

    def rep(self):
        return (self.createHeader(self.TAG, KeyIDElement.LEN + 1) +
                self.keyid.rep())

# ------------------------------------------------------------------------------
    
class HashAlgorithmsSubpacket(SignatureSubpacket):
    """
    Preferred Hash Algorithms
    """

    TAG = 21

    def __init__(self, d):
        self.d = d
        
    def __str__(self, indent=0):
        return 'preferred hash algorithms (tag %d): %s' % (self.TAG, self.d.encode('hex'))
    
    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------
    
class CompressionAlgorithmsSubpacket(SignatureSubpacket):
    """
    Preferred Compression Algorithms
    """

    TAG = 22

    def __init__(self, d):
        self.d = d

    def __str__(self, indent=0):
        return 'preferred compression algorithms (tag %d): %s' % (self.TAG,
                                                                  self.d.encode('hex'))

    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------

class ServerPreferencesSubpacket(SignatureSubpacket):
    """
    Key Server Preferences
    """

    TAG = 23
    
    def __init__(self, d):
        self.value = ''
        if ord(d[0]) & 0x80:
            self.value = 'no-modify'
        self.d = d
        
    def __str__(self, indent=0):
        return 'key server preferences (tag %d): %s' % (self.TAG, self.value)

    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------
    
class KeyFlagsSubpacket(SignatureSubpacket):
    """
    Key Flags
    """

    TAG = 27

    def __init__(self, d):
        f = ord(d[0])
        self.value = ''
        if f & 0x01:
            self.value += 'This key may be used to certify other keys. '
        if f & 0x02:
            self.value += 'This key may be used to sign data. '
        if f & 0x04:
            self.value += 'This key may be used to encrypt communications. '
        if f & 0x08:
            self.value += 'This key may be used to encrypt storage. '
        if f & 0x10:
            self.value += ('The private component of this key may have been '
                           'split by a secret-sharing mechanism.')
        if f & 0x20:
            self.value += 'This key may be used for authentication. '
        if f & 0x80:
            self.value += 'The private component of this key may be in the ' +\
                          'possession of more than one person.'
        self.d = d

    def __str__(self, indent=0):
        return 'key flags (tag %d): %s' % (self.TAG, self.value)

    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------

class FeaturesSubpacket(SignatureSubpacket):
    """
    Features
    """

    TAG = 30

    def __init__(self, d):
        self.d = d
        
    def __str__(self, indent=0):
        return 'features (tag %d): %s' % (self.TAG, self.d.encode('hex'))
    
    def rep(self):
        return self.createHeader(self.TAG, len(self.d) + 1) + self.d

# ------------------------------------------------------------------------------

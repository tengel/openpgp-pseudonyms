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

import io
import time
import math

import crypto

# ------------------------------------------------------------------------------

def hashToString(h):
    if h == crypto.HASH_MD5:
        s = 'MD5'
    elif h == crypto.HASH_SHA1:
        s = 'SHA-1'
    elif h == crypto.HASH_RIPEMD:
        s = 'RIPE-MD/160'
    elif h == crypto.HASH_SHA256:
        s = 'SHA256'
    elif h == crypto.HASH_SHA384:
        s = 'SHA384'
    elif h == crypto.HASH_SHA512:
        s = 'SHA512'
    elif h == crypto.HASH_SHA224:
        s = 'SHA224'
    else:
        s = 'unknown'
    s += ' (%d)' % h
    return s

# ------------------------------------------------------------------------------

class Element:
    """
    Base class for data elements.
    """

# ------------------------------------------------------------------------------
    
class ScalarElement(Element):
    """
    Scalar Number
    """

    def __init__(self, d):
        self.value = 0
        if isinstance(d, basestring):
            self.value = crypto.b2i(d)
        elif isinstance(d, int) or isinstance(d, long):
            self.value = d

    def rep(self, octets = 0):
        return crypto.i2b(self.value, octets)

    def __str__(self):
        return str(self.value)

# ------------------------------------------------------------------------------

class MPIElement(Element):
    """
    Multiprecision Integer
    """

    def __init__(self, d):
        if isinstance(d, int) or isinstance(d, long):
            self.value = d
            self.bytes = crypto.i2b(d)
            return
        if isinstance(d, basestring):
            stream = io.BytesIO(d)
        elif isinstance(d, io.BytesIO):
            stream = d
        bits = crypto.b2i(stream.read(2))
        mpiBytes = int(math.ceil(float(bits) / 8))
        self.bytes = stream.read(mpiBytes)
        self.value = crypto.b2i(self.bytes)

    def bits(self):
        temp = self.value
        bits = 0
        while temp > 0:
            bits += 1
            temp >>= 1
        return bits

    def octets(self):
        return int(math.ceil(float(self.bits()) / 8))
        
    def rep(self):
        return crypto.i2b(self.bits(), 2) + crypto.i2b(self.value)
        
    def __str__(self):
        return ('MPI (%d bits): 0x%s' %
                (self.bits(), crypto.i2b(self.value).encode('hex')))

    def __cmp__(self, other):
        return self.value - other.value

# ------------------------------------------------------------------------------

class KeyIDElement(ScalarElement):
    """
    Key ID
    """

    LEN = 8

    def __init__(self, d):
        ScalarElement.__init__(self, d)

    def rep(self):
        return ScalarElement.rep(self, self.LEN)

    def __str__(self):
        return 'KeyID: 0x%016x' % self.value

# ------------------------------------------------------------------------------

class TextElement(Element):
    """
    Text
    """
    
# ------------------------------------------------------------------------------

class TimeElement(ScalarElement):
    """
    Time Field
    """

    LEN = 4

    @classmethod
    def now(self):
        return TimeElement(int(time.time()))

    def __init__(self, p):
        if isinstance(p, basestring) and len(p) != 4:
                raise Exception('invalid time element')
        elif isinstance(p, TimeElement):
            p = p.value
        ScalarElement.__init__(self, p)

    def __str__(self):
        return '%s' % time.ctime(self.value)

    def rep(self):
        return ScalarElement.rep(self, self.LEN)

# ------------------------------------------------------------------------------

class S2KElement(Element):
    def __init__(self, s=None):
        if isinstance(s, basestring):
            s = io.BytesIO(s)
        if isinstance(s, io.BytesIO):
            self.specifier = ord(s.read(1))
            if self.specifier == 0:
                # Simple S2K
                raise Exception('not implemented')
            elif self.specifier == 1:
                # Salted S2K
                raise Exception('not implemented')
            elif self.specifier == 3:
                # Iterated and Salted S2K
                self.hashalgorithm = ord(s.read(1))
                self.salt = s.read(8)
                c = ord(s.read(1))
                self.count = (16 + (c & 15)) << ((c >> 4) + 6);
        if s is None:
            self.specifier = 3
            self.hashalgorithm = crypto.HASH_SHA1
            self.salt = crypto.randomBytes(8)
            self.count = 65536

    def generateKey(self, passphrase, algorithm):
        if self.specifier == 0:
            raise Exception('not implemented')
        elif self.specifier == 1:
            raise Exception('not implemented')
        elif self.specifier == 3:
            hashdata = ''
            m = self.salt + passphrase
            bytes = 0
            while bytes < self.count:
                for i in range(0, len(m)):
                    hashdata += m[i]
                    bytes += 1
                    if bytes == self.count:
                        break
            self.key = crypto.hash(hashdata, self.hashalgorithm)
            if len(self.key) < crypto.SYMALGORITHM_KEYSIZE[algorithm]:
                self.key += crypto.hash('\x00' + hashdata, self.hashalgorithm)
        else:
            raise Exception('invalid s2k specifier')
        return self.key[:crypto.SYMALGORITHM_KEYSIZE[algorithm]]

    def __str__(self):
        return ('S2K: iterated and salted (3)\n'
                '        Hash algorithm: %s\n'
                '        Salt: %s\n'
                '        Count: %d') % (hashToString(self.hashalgorithm),
                                        self.salt.encode('hex'),
                                        self.count)

    def rep(self):
        return (chr(self.specifier) + chr(self.hashalgorithm) + self.salt +
                chr(96))

# ------------------------------------------------------------------------------

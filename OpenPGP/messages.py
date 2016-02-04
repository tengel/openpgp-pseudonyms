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

import re
import textwrap

from elements import *
from packets import *

SEP = '-----'

# ------------------------------------------------------------------------------

def fromRadix64(radix64, passphraseCallback=None):
    """
    Parse a radix64 PGP message
    """
    radix64 = radix64.replace('\r\n', '\n')
    match = re.match('.*' + SEP + 'BEGIN (.*)' + SEP +
                     '.*\n\n(.*)\n(=\S\S\S\S)\n' + SEP + '.*',
                     radix64, re.DOTALL | re.MULTILINE)
    if match is None:
        raise Exception('invalid format')
    header = match.group(1)
    if header == PublicKeyMessage.HEADER:
        m = PublicKeyMessage()
    elif header == SecretKeyMessage.HEADER:
        m = SecretKeyMessage()
    elif header == SignatureMessage.HEADER:
        m = SignatureMessage()
    elif header == BlindMessageMessage.HEADER:
        m = BlindMessageMessage()
    elif header == BlindSignatureMessage.HEADER:
        m = BlindSignatureMessage()
    elif header == Message.HEADER:
        m = Message()
    else:
        raise Exception('invalid header')

    stream = io.BytesIO(match.group(2).decode('base64'))

    while True:
        p = Packet.parse(stream, passphraseCallback)
        if p is None:
            break
        m.packets[p.TAG] = p
    return m

# ------------------------------------------------------------------------------

def calcCRC24(octets):
    CRC24_INIT = 0xB704CE
    CRC24_POLY = 0x1864CFBL

    crc = CRC24_INIT
    for octet in octets:
        crc ^= ord(octet) << 16
        for i in range(0, 8):
            crc <<= 1;
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    return crc & 0xFFFFFF

# ------------------------------------------------------------------------------
    
class Message:
    """
    A OpenPGP message consisting of several packets.

    """
    SEP = '-----'
    HEADER = 'PGP MESSAGE'

    def __init__(self):
        self.packets = {}

    @classmethod
    def fromPackets(self, packets):
        m = Message()
        for p in packets:
            m.packets[p.TAG] = p
        return m


    def rep(self):
        data = ''
        for p in self.packets.values():
            data += p.rep()
        base64 = '\n'.join(textwrap.wrap(data.encode('base64').replace('\n', ''),
                                         64))
        crc24 = ScalarElement(calcCRC24(data)).rep(3).encode('base64')
        return (self.SEP + 'BEGIN ' + self.HEADER + self.SEP + '\n\n' +
                base64 + '\n' +
                '=' + crc24 +
                self.SEP + 'END ' + self.HEADER + self.SEP + '\n')

    def __str__(self):
        s = ''
        for p in self.packets:
            s += self.packets[p].__str__()
        return s

# ------------------------------------------------------------------------------

class PublicKeyMessage(Message):
    HEADER = 'PGP PUBLIC KEY BLOCK'

    def verifySignature(self):
        data = (self.packets[PublicKeyPacket.TAG].hashdata() +
                self.packets[UserIDPacket.TAG].hashdata() +
                self.packets[SignaturePacket.TAG].hashdata())

        plainhash = crypto.hash(
            data,
            self.packets[SignaturePacket.TAG].hashAlgorithm.value)
        if self.packets[SignaturePacket.TAG].hashLeftTwo != plainhash[0:2]:
            return False
        sig = self.packets[SignaturePacket.TAG].sig.value
        codedhash = encoding.pkcs15(
            plainhash,
            self.packets[PublicKeyPacket.TAG].n.bits(),
            self.packets[SignaturePacket.TAG].hashAlgorithm.value)
        codedhashInt = ScalarElement(codedhash).value
        rsaN = self.packets[PublicKeyPacket.TAG].n.value
        rsaE = self.packets[PublicKeyPacket.TAG].e.value
        return crypto.rsaVerify(sig, codedhashInt, rsaE, rsaN)
        

    def computeSignature(self, secretKey):
        data = (self.packets[PublicKeyPacket.TAG].hashdata() +
                self.packets[UserIDPacket.TAG].hashdata() +
                self.packets[SignaturePacket.TAG].hashdata())
        plainhash = crypto.hash(
            data, self.packets[SignaturePacket.TAG].hashAlgorithm.value)
        codedhash = encoding.pkcs15(
            plainhash,
            self.packets[PublicKeyPacket.TAG].n.bits(),
            self.packets[SignaturePacket.TAG].hashAlgorithm.value)
        codedhashInt = ScalarElement(codedhash).value
        rsaN = secretKey.packets[SecretKeyPacket.TAG].n.value
        rsaD = secretKey.packets[SecretKeyPacket.TAG].d.value
        sig = crypto.rsaSign(codedhashInt, rsaD, rsaN)
        return plainhash[0:2], MPIElement(sig)


    def creationTime(self):
        return self.packets[PublicKeyPacket.TAG].created


    def expirationTime(self):
        return TimeElement(self.creationTime().value +
                           self.packets[SignaturePacket.TAG].hashedSubpackets.get(KeyExpirationSubpacket.TAG).value)
        

    def isExpired(self):
        return TimeElement.now().value > self.expirationTime().value

    @classmethod
    def fromPackets(self, packets):
        m = PublicKeyMessage()
        for p in packets:
            m.packets[p.TAG] = p
        return m

# ------------------------------------------------------------------------------

class SecretKeyMessage(PublicKeyMessage):
    HEADER = 'PGP PRIVATE KEY BLOCK'

    def rep(self, passphrase=None):
        self.packets[SecretKeyPacket.TAG].passphrase = passphrase
        return Message.rep(self)

    @classmethod
    def fromPackets(self, packets):
        m = SecretKeyMessage()
        for p in packets:
            m.packets[p.TAG] = p
        return m

# ------------------------------------------------------------------------------

class SignatureMessage(Message):
    HEADER = 'PGP SIGNATURE'

    @classmethod
    def fromPackets(self, packets):
        m = SignatureMessage()
        for p in packets:
            m.packets[p.TAG] = p
        return m
    
# ------------------------------------------------------------------------------

class BlindSignatureMessage(Message):
    HEADER = 'PGP BLIND SIGNATURE'

    @classmethod
    def fromPackets(self, packets):
        m = BlindSignatureMessage()
        for p in packets:
            m.packets[p.TAG] = p
        return m

# ------------------------------------------------------------------------------

class BlindMessageMessage(Message):
    HEADER = 'PGP BLIND MESSAGE'

    @classmethod
    def fromPackets(self, packets):
        m = BlindMessageMessage()
        for p in packets:
            m.packets[p.TAG] = p
        return m
    
# ------------------------------------------------------------------------------

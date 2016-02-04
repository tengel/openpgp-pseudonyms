#!/usr/bin/python
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

import sys
sys.path.append('..')
import io

import unittest
from OpenPGP import *

# ------------------------------------------------------------------------------

class TestPackets(unittest.TestCase):

    def testPacketHeader(self):
        h = packets.Packet.createHeader(1, 2098)
        self.assertTrue(len(h), 3)
        self.assertTrue(ord(h[0]) & 0x80, 0x80)
        self.assertTrue(ord(h[0]) & 0x40, 0x40)
        self.assertTrue(ord(h[0]) & 0x3f, 1)
        self.assertTrue(h[1:2], '\xc8\x32')
        packets.Packet.parse(io.BytesIO(h))
        h = packets.Packet.createHeader(1, 191)
        self.assertTrue(len(h), 2)
        self.assertTrue(ord(h[0]) & 0x80, 0x80)
        self.assertTrue(ord(h[0]) & 0x40, 0x40)
        self.assertTrue(ord(h[0]) & 0x3f, 1)
        self.assertTrue(h[1], '\xbf')
        packets.Packet.parse(io.BytesIO(h))


    def testUserIDPacket(self):
        p = packets.UserIDPacket(io.BytesIO('Foobar'), 6)
        self.assertEqual(p.id, 'Foobar')
        self.assertEqual(p.hashdata(), '\xb4\x00\x00\x00\x06Foobar')
        self.assertEqual(p.rep(), '\xcd\x06Foobar')
        self.assertEqual(packets.Packet.parse(io.BytesIO(p.rep())).id, 'Foobar')
        self.assertEqual(packets.Packet.parse(io.BytesIO('\xb4\x06Foobar')).id,
                         'Foobar')


    def testSignaturePacket(self):
        s1 = packets.SignaturePacket()
        s1.version = elements.ScalarElement(4)
        s1.signatureType = elements.ScalarElement(0)
        s1.pubAlgorithm = elements.ScalarElement(1)
        s1.hashAlgorithm = elements.ScalarElement(2)
        s1.hashedSubpackets.add(subpackets.CreationTimeSubpacket(23))
        s1.subpackets.add(subpackets.IssuerSubpacket(1234))
        s1.hashLeftTwo = '\x01\x02'
        s1.sig = elements.MPIElement(2**256)

        self.assertEqual(s1.version.value, 4)
        self.assertEqual(s1.signatureType.value, 0x00)
        self.assertEqual(s1.pubAlgorithm.value, 1)
        self.assertEqual(s1.hashAlgorithm.value, 2)
        self.assertEqual(len(s1.hashedSubpackets.packets), 1)
        self.assertEqual(
            s1.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).value,
            23)
        self.assertEqual(len(s1.subpackets.packets), 1)
        self.assertEqual(
            s1.subpackets.get(subpackets.IssuerSubpacket.TAG).keyid.value, 1234)
        self.assertEqual(s1.hashLeftTwo, '\x01\x02')
        self.assertEqual(s1.sig.value, 2**256)

        s2 = packets.SignaturePacket.fromData(io.BytesIO(s1.rep()[2:]))
        self.assertEqual(s2.version.value, 4)
        self.assertEqual(s2.signatureType.value, 0x00)
        self.assertEqual(s2.pubAlgorithm.value, 1)
        self.assertEqual(s2.hashAlgorithm.value, 2)
        self.assertEqual(len(s2.hashedSubpackets.packets), 1)
        self.assertEqual(
            s2.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).value, 23)
        self.assertEqual(len(s2.subpackets.packets), 1)
        self.assertEqual(
            s2.subpackets.get(subpackets.IssuerSubpacket.TAG).keyid.value, 1234)
        self.assertEqual(s2.hashLeftTwo, '\x01\x02')
        self.assertEqual(s2.sig.value, 2**256)


    def testBlindMessageMessage(self):
        mpi = elements.MPIElement(23)
        packet = packets.BlindMessagePacket()
        packet.m = mpi
        m = messages.BlindMessageMessage()
        m.packets[packet.TAG] = packet


    def testNymPacket(self):
        n = packets.NymPacket()
        n.id = 'Foo Bar'
        n.n = elements.MPIElement(23)
        n1 = packets.NymPacket.fromData(io.BytesIO(n.rep()[2:]))
        self.assertEqual(n1.id, n.id)
        self.assertEqual(n1.n, n.n)
        self.assertEqual(n.hashdata(), '\x07Foo Bar\x00\x05\x17')

        secretKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_secret_openpgp.txt', 'r').read())
        publicKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())
        n.computeSignature(secretKey)
        self.assertTrue(n.isValid(publicKey))

    def testPublicKeyPacket(self):
        p1 = packets.PublicKeyPacket.fromParameter(elements.MPIElement(1234),
                                                  elements.MPIElement(3))
        p2 = packets.PublicKeyPacket(io.BytesIO(p1.rep()[2:]))
        self.assertEqual(p1.version.value, p2.version.value)
        self.assertEqual(p1.created.value, p2.created.value)
        self.assertEqual(p1.algorithm.value, p2.algorithm.value)
        self.assertEqual(p1.n.value, p2.n.value)
        self.assertEqual(p1.e.value, p2.e.value)

    def testSecretKeyPacket(self):
        s1 = packets.SecretKeyPacket.fromParameter(elements.MPIElement(1),
                                                   elements.MPIElement(2),
                                                   elements.MPIElement(3),
                                                   elements.MPIElement(4),
                                                   elements.MPIElement(5),
                                                   elements.MPIElement(6))
        s2 = packets.SecretKeyPacket(io.BytesIO(s1.rep()[2:]))
        self.assertEqual(s1.version.value, s2.version.value)
        self.assertEqual(s1.created.value, s2.created.value)
        self.assertEqual(s1.algorithm.value, s2.algorithm.value)
        self.assertEqual(s1.n.value, s2.n.value)
        self.assertEqual(s1.e.value, s2.e.value)
        self.assertEqual(s1.d.value, s2.d.value)
        self.assertEqual(s1.p.value, s2.p.value)
        self.assertEqual(s1.q.value, s2.q.value)
        self.assertEqual(s1.u.value, s2.u.value)

    def testSecretKeyEncrypted(self):
        key = messages.fromRadix64(
            open('testdata/foobar-bar.com_secret_2048encrypted.txt', 'r').read(),
            passphraseCallback)
        key = messages.fromRadix64(
            open('testdata/secretkey_3des.txt', 'r').read(),
            passphraseCallback)
        key = messages.fromRadix64(
            open('testdata/secretkey_blowfish.txt', 'r').read(),
            passphraseCallback)
        key = messages.fromRadix64(
            open('testdata/secretkey_aes128.txt', 'r').read(),
            passphraseCallback)
        key = messages.fromRadix64(
            open('testdata/secretkey_aes192.txt', 'r').read(),
            passphraseCallback)
        key = messages.fromRadix64(
            open('testdata/secretkey_aes256.txt', 'r').read(),
            passphraseCallback)
        p1 = key.packets[TAG_SECKEY]
        p2 = packets.SecretKeyPacket(io.BytesIO(p1.rep()[3:]))
        p2bin = p1.rep('secret')
        p2 = packets.SecretKeyPacket(io.BytesIO(p2bin[3:]), len(p2bin) - 3,
                                     passphraseCallback)
        s1 = packets.SecretKeyPacket.fromParameter(elements.MPIElement(1),
                                                   elements.MPIElement(2),
                                                   elements.MPIElement(3),
                                                   elements.MPIElement(4),
                                                   elements.MPIElement(5),
                                                   elements.MPIElement(6))
        s1bin = s1.rep('secret')
        s2 = packets.SecretKeyPacket(io.BytesIO(s1bin[2:]), len(s1bin) - 2,
                                     passphraseCallback)

# ------------------------------------------------------------------------------

def passphraseCallback():
    return 'secret'
        
if __name__ == '__main__':
        unittest.main()

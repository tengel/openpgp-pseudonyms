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

import unittest
from OpenPGP import *
import io
import os

# ------------------------------------------------------------------------------

class TestMessages(unittest.TestCase):

    def testReadPublicKey(self):
        radix64 = open('testdata/foo-bar.com_public_openpgp.txt', 'r').read()
        m = messages.fromRadix64(radix64)
        packets = m.packets

        pubkey = packets[TAG_PUBKEY]
        self.assertEqual(pubkey.version.value, 4)
        self.assertEqual(pubkey.created.value, 1319900404)
        self.assertEqual(pubkey.algorithm.value, 1)
        self.assertEqual(pubkey.n.bytes,
                         '\xbd\xb9\x28\x4d\xa8\x52\xeb\x65\x85\x47\x95\x2e\x6b'
                         '\xaa\x4c\x71\x91\x12\x01\x91\x45\xb9\xe6\xf8\x1c\xee'
                         '\x06\x6a\xac\xef\x80\xf6\x9e\xd2\xaa\x3c\xcd\x0f\x2e'
                         '\x9b\x45\x14\x1a\xe7\x3d\x65\x7c\xf0\x21\xa5\x7e\xe5'
                         '\x21\x51\x93\x9b\x44\x6d\x41\xc0\x5a\xb5\x9e\x7f\x33'
                         '\xf0\xcd\xd5\x92\xe6\x5c\xf1\xcd\x40\x4b\x25\x73\xb3'
                         '\x17\x68\x1b\x5e\x6d\xc8\x40\x0e\x93\x13\xee\x4e\xb0'
                         '\x0e\x23\x8e\xbb\xe7\xda\x1e\xcf\x32\xea\x43\x6a\x4c'
                         '\xcf\x2e\x14\xa0\xef\x83\xd2\x96\x2f\x1c\x36\xf2\xcf'
                         '\x8b\xc7\xfd\xcb\x39\x83\x1e\xba\xd4\x40\x43')
        self.assertEqual(pubkey.e.bytes, '\x01\x00\x01')
        self.assertEqual(pubkey.hashdata()[0], '\x99')
        self.assertEqual(pubkey.hashdata()[1:3], '\x00\x8d')
        self.assertEqual(pubkey.fingerprint(),
                         '\xE5\x8A\x16\x73\x7F\x5A\xBB\x22\x28\xA1\x59\x01\x7B'
                         '\x4F\x9A\xAF\x42\x65\x20\x10')
        self.assertEqual(pubkey.keyID(), '\x7B\x4F\x9A\xAF\x42\x65\x20\x10')

        userID = packets[TAG_USERID]
        self.assertEqual(userID.id, 'Foo Bar <foo@bar.com>')
        self.assertEqual(userID.hashdata(),
                         '\xb4\x00\x00\x00\x15Foo Bar <foo@bar.com>')

        signature = packets[TAG_SIGNATURE]
        self.assertEqual(signature.version.value, 4)
        self.assertEqual(signature.signatureType.value, 0x13)
        self.assertEqual(signature.pubAlgorithm.value, 1)
        self.assertEqual(signature.hashAlgorithm.value, 2)
        self.assertEqual(len(signature.hashedSubpackets.packets), 8)
        self.assertEqual(len(signature.subpackets.packets), 1)
        self.assertEqual(signature.hashLeftTwo, '\xff\x5f')
        self.assertEqual(signature.sig.bytes,
                         '\x06\xdb\x99\xea\x71\x83\xc4\x38\x99\xc9\x1c\x26\xc4'
                         '\xe9\xee\x7f\xd5\x7c\x85\xcb\x34\x60\xa2\x4b\xf1\x15'
                         '\xa1\x33\xb2\x1a\x54\xd3\x1c\x5a\x87\xe2\x8d\x7a\x52'
                         '\xaa\xb1\x3e\x5b\xd3\x2b\x0c\xe1\xb3\xf3\x5b\xf0\x2a'
                         '\xe3\x90\xc2\xd4\xc0\x8c\xb0\x74\x3b\x35\x61\x56\x87'
                         '\xac\xdd\x31\x37\x84\x12\x39\x5e\x82\x4e\x19\x7e\xf0'
                         '\xe6\xff\x88\x20\x49\xa9\x64\x3c\x2e\xf8\xa4\xb6\x4b'
                         '\x98\x8a\xf6\xa6\x21\x24\x36\x78\x80\x6e\x93\x68\xaa'
                         '\x78\x56\x0d\x62\x53\x69\xa9\x32\x0f\xad\x7b\x9f\x0b'
                         '\x19\x75\x5d\x72\x6e\xf1\x08\xb4\x51\xbd\x56')
        self.assertEqual(signature.hashdata()[-6:], '\x04\xff\x00\x00\x00\x2e')
        self.assertTrue(m.verifySignature())
        self.assertTrue(m.isExpired())
        
    
    def testReadSecretKey(self):
        radix64 = open('testdata/foo-bar.com_secret_openpgp.txt', 'r').read()
        m = messages.fromRadix64(radix64)
        packets = m.packets

        secretkey = packets[TAG_SECKEY]
        self.assertEqual(secretkey.version.value, 4)
        self.assertEqual(secretkey.created.value, 1319900404)
        self.assertEqual(secretkey.algorithm.value, 1)
        self.assertEqual(secretkey.n.bytes,
                         '\xbd\xb9\x28\x4d\xa8\x52\xeb\x65\x85\x47\x95\x2e\x6b'
                         '\xaa\x4c\x71\x91\x12\x01\x91\x45\xb9\xe6\xf8\x1c\xee'
                         '\x06\x6a\xac\xef\x80\xf6\x9e\xd2\xaa\x3c\xcd\x0f\x2e'
                         '\x9b\x45\x14\x1a\xe7\x3d\x65\x7c\xf0\x21\xa5\x7e\xe5'
                         '\x21\x51\x93\x9b\x44\x6d\x41\xc0\x5a\xb5\x9e\x7f\x33'
                         '\xf0\xcd\xd5\x92\xe6\x5c\xf1\xcd\x40\x4b\x25\x73\xb3'
                         '\x17\x68\x1b\x5e\x6d\xc8\x40\x0e\x93\x13\xee\x4e\xb0'
                         '\x0e\x23\x8e\xbb\xe7\xda\x1e\xcf\x32\xea\x43\x6a\x4c'
                         '\xcf\x2e\x14\xa0\xef\x83\xd2\x96\x2f\x1c\x36\xf2\xcf'
                         '\x8b\xc7\xfd\xcb\x39\x83\x1e\xba\xd4\x40\x43')
        self.assertEqual(secretkey.e.bytes, '\x01\x00\x01')
        self.assertEqual(secretkey.d.bytes,
                         '\x2e\xee\x43\xe1\x7d\xdf\x51\x1a\x72\x4f\x24\x40\x70'
                         '\xe2\x95\xf9\x4b\xc4\xf3\xfd\x4f\x0d\xae\xec\x36\x1f'
                         '\xcd\x17\x8b\x42\xcd\x98\x73\xee\x31\xad\x4b\x9e\x53'
                         '\x4d\x96\x57\x64\x56\x4a\x32\x36\x27\x22\x73\x91\x41'
                         '\xb5\xad\xbb\xc1\x1f\x3a\x95\x96\xb2\xf9\x95\x44\x7d'
                         '\xf7\x82\x2d\xc9\x39\xc9\x87\x94\x91\x5a\x91\x1f\xee'
                         '\x0e\xc4\xe4\xe1\xb6\x83\xf5\x40\xce\x77\xfd\x26\x7d'
                         '\x0b\xdc\xbe\x94\xdf\x93\x0e\xce\xba\x12\x27\x66\x9c'
                         '\x3c\xc9\x8b\x90\xd0\xb7\xf4\x14\x89\x2b\xb7\x1c\x0e'
                         '\xbc\x70\xd6\x4c\x0b\xf0\x11\xe9\x7a\x02\x25')
        self.assertEqual(secretkey.p.bytes,
                         '\xda\x15\x61\x19\x0c\x03\x63\xcf\xc7\x84\x7a\xcc\xf8'
                         '\x17\xd5\x89\x72\xa0\xda\xef\xbe\xc8\x99\xe0\x04\x96'
                         '\x5b\x30\x5f\x74\x18\x78\xe7\xf0\x06\x2a\x42\x65\xb5'
                         '\xcc\x99\x07\x0a\x81\xac\xcf\x7a\xa9\xf1\x17\x21\x9e'
                         '\x2e\x13\x26\x4c\xd1\xfe\x6e\x75\x99\xfd\x51\x97')
        self.assertEqual(secretkey.q.bytes,
                         '\xde\xb5\x7f\xef\x17\x8e\x9c\xbb\x81\x06\x62\xcd\x50'
                         '\x84\x63\x6f\x52\x0b\x79\x38\xc1\xa0\x5d\xf4\x49\xc1'
                         '\x44\x29\x56\xa1\xcd\x45\x15\xa0\xcb\x2e\xef\x84\xf2'
                         '\x35\xfc\x80\x85\xe5\x6d\xb1\x22\x13\x25\xe1\x02\xfc'
                         '\x17\x72\x9f\x33\x4e\xfd\x49\xa4\x88\x44\x04\x35')
        self.assertEqual(secretkey.u.bytes,
                         '\xb9\x21\x36\xf1\xe2\xc5\xca\xd5\x82\x31\x2a\xdd\xce'
                         '\x45\x38\x2c\x89\x42\xb0\x95\xbf\x10\x1c\x11\x92\xf1'
                         '\x55\xc2\xa1\xdc\x43\x62\x6c\x55\xd5\x3d\x20\x68\x5a'
                         '\x50\x56\x8c\x00\x05\xf5\xfa\x28\x3f\x6d\xa6\xc0\x5f'
                         '\x34\x59\xf0\x05\xf5\x0d\xc3\xef\xbe\x97\x4c\x32')
        self.assertEqual(secretkey.checksum, '\x9e\x47')


    def testKeySignature(self):
        secretKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_secret_openpgp.txt', 'r').read())
        pubKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())

        h, s = pubKey.computeSignature(secretKey)
        self.assertEqual(h,
                         pubKey.packets[TAG_SIGNATURE].hashLeftTwo)
        self.assertEqual(s, pubKey.packets[TAG_SIGNATURE].sig)
        self.assertEqual(s.bytes,
                         '\x06\xdb\x99\xea\x71\x83\xc4\x38\x99\xc9\x1c\x26\xc4'
                         '\xe9\xee\x7f\xd5\x7c\x85\xcb\x34\x60\xa2\x4b\xf1\x15'
                         '\xa1\x33\xb2\x1a\x54\xd3\x1c\x5a\x87\xe2\x8d\x7a\x52'
                         '\xaa\xb1\x3e\x5b\xd3\x2b\x0c\xe1\xb3\xf3\x5b\xf0\x2a'
                         '\xe3\x90\xc2\xd4\xc0\x8c\xb0\x74\x3b\x35\x61\x56\x87'
                         '\xac\xdd\x31\x37\x84\x12\x39\x5e\x82\x4e\x19\x7e\xf0'
                         '\xe6\xff\x88\x20\x49\xa9\x64\x3c\x2e\xf8\xa4\xb6\x4b'
                         '\x98\x8a\xf6\xa6\x21\x24\x36\x78\x80\x6e\x93\x68\xaa'
                         '\x78\x56\x0d\x62\x53\x69\xa9\x32\x0f\xad\x7b\x9f\x0b'
                         '\x19\x75\x5d\x72\x6e\xf1\x08\xb4\x51\xbd\x56')
        self.assertTrue(pubKey.verifySignature())

        secretKey  = messages.fromRadix64(
            open('testdata/foobar-bar.com_secret_2048.txt', 'r').read())
        pubKey  = messages.fromRadix64(
            open('testdata/foobar-bar.com_public_2048.txt', 'r').read())

        h, s = pubKey.computeSignature(secretKey)
        self.assertEqual(h, pubKey.packets[TAG_SIGNATURE].hashLeftTwo)
        self.assertEqual(s, pubKey.packets[TAG_SIGNATURE].sig)
        self.assertTrue(pubKey.verifySignature())


    def testReadSignature(self):
        text = open('testdata/detached_signature.txt', 'r').read()
        message = messages.fromRadix64(text)
        publicKey  = messages.fromRadix64(
           open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())

        sig = message.packets[TAG_SIGNATURE]
        self.assertEqual(sig.version.value, 4)
        self.assertEqual(sig.signatureType.value, 0x00)
        self.assertEqual(sig.pubAlgorithm.value, 1)
        self.assertEqual(sig.hashAlgorithm.value, 2)
        self.assertEqual(len(sig.hashedSubpackets.packets), 1)
        self.assertEqual(
            sig.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).value,
            1320532005)
        self.assertEqual(
            sig.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).rep(),
            '\x05\x02\x4e\xb5\xb8\x25')
        self.assertEqual(len(sig.subpackets.packets), 1)
        self.assertEqual(
            sig.subpackets.get(subpackets.IssuerSubpacket.TAG).keyid.value,
            0x7B4F9AAF42652010)
        self.assertEqual(sig.hashLeftTwo, '\x53\x16')

        s2 = packets.SignaturePacket.fromData(io.BytesIO(sig.rep()[2:]))
        self.assertEqual(s2.version.value, 4)
        self.assertEqual(s2.signatureType.value, 0x00)
        self.assertEqual(s2.pubAlgorithm.value, 1)
        self.assertEqual(s2.hashAlgorithm.value, 2)
        self.assertEqual(len(s2.hashedSubpackets.packets), 1)
        self.assertEqual(
            s2.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).value,
            1320532005)
        self.assertEqual(
            s2.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG).rep(),
            '\x05\x02\x4e\xb5\xb8\x25')
        self.assertEqual(len(s2.subpackets.packets), 1)
        self.assertEqual(
            s2.subpackets.get(subpackets.IssuerSubpacket.TAG).keyid.value,
            0x7B4F9AAF42652010)
        self.assertEqual(s2.hashLeftTwo, '\x53\x16')

        self.assertTrue(verifySignature('Foobar\n', message, publicKey))


    def testMessage(self):
        text = open('testdata/detached_signature.txt', 'r').read()
        message = messages.fromRadix64(text)
        message = messages.fromRadix64(message.rep())


    def testCRC24(self):
        self.assertEqual(messages.calcCRC24('Foobar'), 12017810)

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

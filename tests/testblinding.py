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

import blinding
from OpenPGP import *
import crypto
import blindca

# ------------------------------------------------------------------------------

class TestBlinding(unittest.TestCase):

    def testBlinding(self):
        secretKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_secret_openpgp.txt', 'r').read())
        publicKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())

        data = 'The quick brown fox jumps over the lazy dog\n'
        sigTime = elements.TimeElement.now()

        r, hashTwo, newSigTime, blinded = blinding.blind(publicKey, sigTime, data)
        self.assertEqual(sigTime.value, newSigTime.value)
        
        blindSig = crypto.rsaSign(blinded.packets[TAG_BLINDMSG].m.value,
                                  secretKey.packets[TAG_SECKEY].d.value,
                                  publicKey.packets[TAG_PUBKEY].n.value)
        packet = packets.BlindSignaturePacket()
        packet.s = elements.MPIElement(blindSig)
        message = messages.BlindSignatureMessage.fromPackets((packet,))

        s = blinding.unblind(publicKey, sigTime, r, hashTwo, message)
        self.assertTrue(verifySignature(data, s, publicKey))

    def testCASign(self):
        caConfig = blindca.Config()
        caConfig.secretKey = 'testdata/foo-bar.com_secret_openpgp.txt'
        caConfig.publicKey = 'testdata/foo-bar.com_public_openpgp.txt'
        ca = blindca.BlindCA(caConfig)
        publicKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())
        data = 'The quick brown fox jumps over the lazy dog\n'

        r, hashtwo, sigTime, blinded = blinding.blind(publicKey, None, data)
        blindSig = ca.sign(blinded)
        sig = blinding.unblind(publicKey, sigTime, r, hashtwo, blindSig)

        self.assertTrue(verifySignature(data, sig, publicKey))
        self.assertTrue(sigTime.value >= publicKey.creationTime().value)
        self.assertTrue(sigTime.value <= publicKey.expirationTime().value)

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

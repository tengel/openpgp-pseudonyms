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

import blindca
import crypto
from OpenPGP import *

# ------------------------------------------------------------------------------

class TestBlindCa(unittest.TestCase):

    def setUp(self):
        self.caConfig = blindca.Config()
        self.caConfig.secretKey = 'testdata/foo-bar.com_secret_openpgp.txt'
        self.caConfig.publicKey = 'testdata/foo-bar.com_public_openpgp.txt'
        self.ca = blindca.BlindCA(self.caConfig)


    def testSign(self):
        message = 'The quick brown fox jumps over the lazy dog\n'

        packet = packets.BlindMessagePacket()
        packet.m = elements.MPIElement(elements.ScalarElement(message).value)
        blindMessage = messages.BlindMessageMessage()
        blindMessage.packets[packet.TAG] = packet

        sigMessage = self.ca.sign(blindMessage)

        self.assertTrue(crypto.rsaVerify(
                sigMessage.packets[TAG_BLINDSIG].s.value,
                packet.m.value,
                self.ca.secretKey.packets[TAG_SECKEY].e.value,
                self.ca.secretKey.packets[TAG_SECKEY].n.value))

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

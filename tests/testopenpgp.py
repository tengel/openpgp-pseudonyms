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


class TestOpenPGP(unittest.TestCase):

    def testSign(self):
        m = 'The quick brown fox jumps over the lazy dog\n'
        publicKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_public_openpgp.txt', 'r').read())
        secretKey  = messages.fromRadix64(
            open('testdata/foo-bar.com_secret_openpgp.txt', 'r').read())
        signature = computeSignature(m, secretKey)
        self.assertTrue(verifySignature(m, signature, publicKey))
        self.assertFalse(verifySignature(m[1:], signature, publicKey))
        open('message.asc', 'w').write(m)
        open('signature.asc', 'w').write(signature.rep())
        self.assertEqual(
            os.system('gpg --verify signature.asc message.asc 2>/dev/null'), 0)
        os.unlink('message.asc')
        os.unlink('signature.asc')

        publicKey  = messages.fromRadix64(
            open('testdata/foobar-bar.com_public_2048.txt', 'r').read())
        secretKey  = messages.fromRadix64(
            open('testdata/foobar-bar.com_secret_2048.txt', 'r').read())
        signature = computeSignature(m, secretKey)
        self.assertTrue(verifySignature(m, signature, publicKey))
        self.assertFalse(verifySignature(m[1:], signature, publicKey))
        open('message.asc', 'w').write(m)
        open('signature.asc', 'w').write(signature.rep())
        self.assertEqual(
            os.system('gpg --verify signature.asc message.asc 2>/dev/null'), 0)
        os.unlink('message.asc')
        os.unlink('signature.asc')




#    def testToString(self):
#        self.assertEqual(openpgp.algorithmToString(openpgp.ALGORITHM_RSA),
#                         'RSA (1)')

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

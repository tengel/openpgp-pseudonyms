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
from encoding import *
import crypto

# ------------------------------------------------------------------------------

class TestEncoding(unittest.TestCase):

    def testEcash(self):
        self.assertTrue(len(ecash('foobar', 1024, crypto.HASH_SHA1)) * 8 <= 1024)
        self.assertTrue(ecash('foobar', 1024, crypto.HASH_SHA1).startswith('foobar'))

# ------------------------------------------------------------------------------

    def testMgf(self):
        self.assertEqual(len(pssMGF('abc',  1, crypto.HASH_SHA1)), 1)
        self.assertEqual(len(pssMGF('abc',  2, crypto.HASH_SHA1)), 2)
        self.assertEqual(len(pssMGF('abc',  3, crypto.HASH_SHA1)), 3)
        self.assertEqual(len(pssMGF('abc',  4, crypto.HASH_SHA1)), 4)
        self.assertEqual(len(pssMGF('abc', 19, crypto.HASH_SHA1)), 19)
        self.assertEqual(len(pssMGF('abc', 20, crypto.HASH_SHA1)), 20)
        self.assertEqual(len(pssMGF('abc', 21, crypto.HASH_SHA1)), 21)
        self.assertEqual(len(pssMGF('abc', 22, crypto.HASH_SHA1)), 22)
        self.assertEqual(pssMGF('abc',  4, crypto.HASH_SHA1).encode('hex'),
                         'a03eb8ac')
        self.assertEqual(
            pssMGF('abcdefghijklmnopqrst', 43, crypto.HASH_SHA1).encode('hex'),
            '23cf4b6d0149c1edfe4444807deb454e1e15369437679463961c86426180c0736dabd'
            'cbb38464e1cca90df')
        
# ------------------------------------------------------------------------------

    def testEmsapss(self):
        self.assertEqual(len(pssEncode('abcdef', 20, 512, crypto.HASH_SHA1)), 64)
        self.assertEqual(len(pssEncode('abcdef', 20, 513, crypto.HASH_SHA1)), 65)
        self.assertEqual(len(pssEncode('abcdef', 20, 511, crypto.HASH_SHA1)), 64)
        M = 'Foobar'
        EM = pssEncode(M, 20, 512, crypto.HASH_SHA1)
        self.assertTrue(pssVerify(M, EM, 20, 512, crypto.HASH_SHA1))
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 512, crypto.HASH_SHA1),
                                  20, 512, crypto.HASH_SHA1))
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 513, crypto.HASH_SHA1),
                                  20, 513, crypto.HASH_SHA1))
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 511, crypto.HASH_SHA1),
                                  20, 511, crypto.HASH_SHA1))
        self.assertFalse(pssVerify('FooBar', EM, 20, 512, crypto.HASH_SHA1))

        
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 512, crypto.HASH_MD5),
                                  20, 512, crypto.HASH_MD5))
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 512, crypto.HASH_SHA256),
                                  20, 512, crypto.HASH_SHA256))
        self.assertTrue(pssVerify(M,
                                  pssEncode(M, 20, 512, crypto.HASH_SHA224),
                                  20, 512, crypto.HASH_SHA224))

        self.assertTrue(
            pssVerify(M,
                      hashEncode(M, 512, crypto.HASH_MD5, ENCODING_PKCSPSS), 
                      16, 512, crypto.HASH_MD5))
        self.assertTrue(
            pssVerify(M,
                      hashEncode(M, 512, crypto.HASH_SHA1, ENCODING_PKCSPSS),
                      20, 512, crypto.HASH_SHA1))
        self.assertTrue(
           pssVerify(M,
                     hashEncode(M, 512, crypto.HASH_SHA224, ENCODING_PKCSPSS),
                     28, 512, crypto.HASH_SHA224))
       
        self.assertTrue(
            pssVerify(M,
                      hashEncode(M, 1024, crypto.HASH_SHA256, ENCODING_PKCSPSS),
                      32, 1024, crypto.HASH_SHA256))
        

# ------------------------------------------------------------------------------

    def testHashEncode(self):
        hashEncode('Foobar', 512, crypto.HASH_MD5, ENCODING_PKCS15)
        hashEncode('Foobar', 512, crypto.HASH_MD5, ENCODING_ECASH)
        hashEncode('Foobar', 512, crypto.HASH_MD5, ENCODING_PKCSPSS)

        hashEncode('Foobar', 512, crypto.HASH_SHA1, ENCODING_PKCS15)
        hashEncode('Foobar', 512, crypto.HASH_SHA1, ENCODING_ECASH)
        hashEncode('Foobar', 512, crypto.HASH_SHA1, ENCODING_PKCSPSS)

        hashEncode('Foobar', 512,  crypto.HASH_SHA256, ENCODING_PKCS15)
        hashEncode('Foobar', 512,  crypto.HASH_SHA256, ENCODING_ECASH)
        hashEncode('Foobar', 1024, crypto.HASH_SHA256, ENCODING_PKCSPSS)

        hashEncode('Foobar', 1024, crypto.HASH_SHA384, ENCODING_PKCS15)
        hashEncode('Foobar', 1024, crypto.HASH_SHA384, ENCODING_ECASH)
        hashEncode('Foobar', 1024, crypto.HASH_SHA384, ENCODING_PKCSPSS)

        hashEncode('Foobar', 1024, crypto.HASH_SHA512, ENCODING_PKCS15)
        hashEncode('Foobar', 1024, crypto.HASH_SHA512, ENCODING_ECASH)
        hashEncode('Foobar', 2048, crypto.HASH_SHA512, ENCODING_PKCSPSS)

        hashEncode('Foobar', 1024, crypto.HASH_SHA224, ENCODING_PKCS15)
        hashEncode('Foobar', 1024, crypto.HASH_SHA224, ENCODING_ECASH)
        hashEncode('Foobar', 1024, crypto.HASH_SHA224, ENCODING_PKCSPSS)
        
# ------------------------------------------------------------------------------
        
if __name__ == '__main__':
        unittest.main()


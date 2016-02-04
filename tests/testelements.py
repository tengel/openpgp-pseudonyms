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

class TestElements(unittest.TestCase):
    
    def testScalarElement(self):
        self.assertEqual(elements.ScalarElement('\x12').value, 18)
        self.assertEqual(elements.ScalarElement('\x12\x34').value, 4660)
        self.assertEqual(elements.ScalarElement('\x12\x34\x56').value, 1193046)
        self.assertEqual(elements.ScalarElement('\x12\x34\x56\x78').value,
                         305419896)
        
        self.assertEqual(elements.ScalarElement(18).rep(), '\x12')
        self.assertEqual(elements.ScalarElement(4660).rep(), '\x12\x34')
        self.assertEqual(elements.ScalarElement(1193046).rep(), '\x12\x34\x56')
        self.assertEqual(elements.ScalarElement(305419896).rep(),
                         '\x12\x34\x56\x78')
        self.assertEqual(elements.ScalarElement(18).rep(2), '\x00\x12')
        self.assertEqual(elements.ScalarElement(18).rep(3), '\x00\x00\x12')
        self.assertEqual(elements.ScalarElement(18).rep(4), '\x00\x00\x00\x12')


    def testMPIElement(self):
        mpi01 = elements.MPIElement('\x00\x01\x01')
        self.assertEqual(mpi01.value, 1)
        self.assertEqual(mpi01.bits(), 1)
        self.assertEqual(mpi01.octets(), 1)
        self.assertEqual(mpi01.bytes, '\x01')
        mpi02 = elements.MPIElement('\x00\x09\x01\xFF')
        self.assertEqual(mpi02.value, 511)
        self.assertEqual(mpi02.bytes, '\x01\xff')
        self.assertEqual(mpi02.bits(), 9)
        self.assertEqual(mpi02.octets(), 2)

        mpi03 = elements.MPIElement(1)
        self.assertEqual(mpi03.rep(), '\x00\x01\x01')
        self.assertEqual(elements.MPIElement(2).rep(), '\x00\x02\x02')
        self.assertEqual(elements.MPIElement(3).rep(), '\x00\x02\x03')
        self.assertEqual(elements.MPIElement(4).rep(), '\x00\x03\x04')
        self.assertEqual(elements.MPIElement(7).rep(), '\x00\x03\x07')
        self.assertEqual(elements.MPIElement(8).rep(), '\x00\x04\x08')
        self.assertEqual(elements.MPIElement(15).rep(), '\x00\x04\x0f')
        self.assertEqual(elements.MPIElement(16).rep(), '\x00\x05\x10')

        self.assertEqual(elements.MPIElement(256).rep(), '\x00\x09\x01\x00')
        self.assertEqual(elements.MPIElement(2**255).rep(),
                         '\x01\x00' + elements.ScalarElement(2**255).rep())

        self.assertTrue(mpi01 < mpi02)
        self.assertTrue(mpi02 > mpi01)
        self.assertTrue(mpi01 != mpi02)
        mpi03 = elements.MPIElement(1)
        self.assertTrue(mpi01 == mpi03)


    def testKeyIDElement(self):
        id = elements.KeyIDElement('\x01\x02\x03\x04\x05\x06\x07\x08')
        self.assertEqual(id.__str__(), 'KeyID: 0x0102030405060708')
        self.assertEqual(id.rep(), '\x01\x02\x03\x04\x05\x06\x07\x08')
        id = elements.KeyIDElement(0x1234)
        self.assertEqual(id.__str__(), 'KeyID: 0x0000000000001234')
        self.assertEqual(id.rep(), '\x00\x00\x00\x00\x00\x00\x12\x34')
        

    def testTimeElement(self):
        te01 = elements.TimeElement('\x00\x00\x00\x00')
        self.assertEqual(te01.__str__(), 'Thu Jan  1 01:00:00 1970')
        te02 = elements.TimeElement(2)
        self.assertEqual(te02.__str__(), 'Thu Jan  1 01:00:02 1970')
        te03 = elements.TimeElement(te02)
        self.assertEqual(te03.__str__(), 'Thu Jan  1 01:00:02 1970')
        self.assertEqual(te03.value, 2)

    def testS2kElement(self):
        s2kstring = '\x03\x02\x96\x24\x3f\xe7\xc3\xb7\x22\x81\x60'
        s2k=elements.S2KElement(s2kstring)
        self.assertEqual(s2k.specifier, 3)
        self.assertEqual(s2k.hashalgorithm, 2)
        self.assertEqual(s2k.salt, '\x96\x24\x3f\xe7\xc3\xb7\x22\x81')
        self.assertEqual(s2k.count, 65536)
        self.assertEqual(s2kstring, s2k.rep())
        self.assertEqual(
            s2k.generateKey('secret',
                            crypto.SYMALGORITHM_CAST5).encode('hex'),
            'ebb7109b9203ce8570722a947d548913')
        self.assertEqual(
            s2k.generateKey('secret',
                            crypto.SYMALGORITHM_AES192).encode('hex'),
            'ebb7109b9203ce8570722a947d5489137a92675032c5264a')
        self.assertEqual(
            s2k.generateKey('secret',
                            crypto.SYMALGORITHM_AES256).encode('hex'),
            'ebb7109b9203ce8570722a947d5489137a92675032c5264a71508ca3aed5e008')
        s2k = elements.S2KElement()
        

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

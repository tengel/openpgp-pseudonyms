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

import unittest

import testcrypto
import testopenpgp
import testelements
import testpackets
import testmessages
import testblindca
import testblinding
import testencoding
import testidserver
import testkeyserver

suite = unittest.TestSuite()

suite.addTest(unittest.makeSuite(testcrypto.TestCrypto))
suite.addTest(unittest.makeSuite(testopenpgp.TestOpenPGP))
suite.addTest(unittest.makeSuite(testelements.TestElements))
suite.addTest(unittest.makeSuite(testpackets.TestPackets))
suite.addTest(unittest.makeSuite(testmessages.TestMessages))
suite.addTest(unittest.makeSuite(testblindca.TestBlindCa))
suite.addTest(unittest.makeSuite(testblinding.TestBlinding))
suite.addTest(unittest.makeSuite(testencoding.TestEncoding))
suite.addTest(unittest.makeSuite(testidserver.TestIDServer))
suite.addTest(unittest.makeSuite(testkeyserver.TestKeyServer))

unittest.TextTestRunner(verbosity=2).run(suite)

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

import blindca
from OpenPGP import *

if len(sys.argv) < 2:
    print >>sys.stderr, 'usage: sign.py <SECRETKEYFILE>'
    sys.exit(2)

caConfig = blindca.Config()
caConfig.secretKey = sys.argv[1]
ca = blindca.BlindCA(caConfig)

blindMessageRadix = sys.stdin.read().strip()
blindMessage = messages.fromRadix64(blindMessageRadix)
blindSig = ca.sign(blindMessage)
print blindSig.rep()

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

import blinding
from OpenPGP import *

if len(sys.argv) != 3:
    print >>sys.stderr, 'usage: unblind.py <RANDOMFILE> <PUBKEYFILE>'
    sys.exit(2)

blindSigRadix = sys.stdin.read().strip()
blindSig = messages.fromRadix64(blindSigRadix)    
randfile = open(sys.argv[1], 'r')
r = elements.ScalarElement(randfile.readline().strip().decode('hex')).value
hashtwo = randfile.readline().strip().decode('hex')
sigTime = elements.TimeElement(int(randfile.readline().strip()))
randfile.close()
publicKey  = messages.fromRadix64(open(sys.argv[2], 'r').read())

sig = blinding.unblind(publicKey, sigTime, r, hashtwo, blindSig)

#print >>sys.stderr, sig
print sig.rep()

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

from OpenPGP import *
import blinding

if len(sys.argv) != 3 and len(sys.argv) != 4:
    print >>sys.stderr, 'usage: blind.py <RANDOMFILE> <PUBKEYFILE> [<TIME>]'
    sys.exit(2)

publicKey  = messages.fromRadix64(open(sys.argv[2], 'r').read())
message = sys.stdin.read()
if len(sys.argv) == 4:
    sigTime = elements.TimeElement(int(sys.argv[3]))
else:
    sigTime = None

r, hashtwo, sigTime, blinded = blinding.blind(publicKey, sigTime, message)

randfile = open(sys.argv[1], 'w')
randfile.write(elements.ScalarElement(r).rep().encode('hex') + '\n')
randfile.write(hashtwo.encode('hex') + '\n')
randfile.write('%d\n' % sigTime.value)
randfile.close()

#print >>sys.stderr, blinded
print blinded.rep()


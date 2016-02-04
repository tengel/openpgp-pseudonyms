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

if len(sys.argv) != 3:
    print >>sys.stderr, 'usage: nym-prepare.py <NYM> <SECRETKEYFILE>'
    sys.exit(2)

secretKey = messages.fromRadix64(open(sys.argv[2], 'r').read())
nym = packets.NymPacket.fromParameter(
    sys.argv[1],
    secretKey.packets[TAG_SECKEY].n)
nym.computeSignature(secretKey)
if not nym.isValid(secretKey):
    print >>sys.stderr, '%s: failed to create nym' % sys.argv[0]
fname = nym.id.replace(' ', '_') + '.nym'
open(fname, 'w').write(messages.Message.fromPackets((nym,)).rep())
sys.stdout.write(nym.rep())

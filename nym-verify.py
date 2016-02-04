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
from os.path import *
from OpenPGP import *

def verifySelfSignature(nym):
    key = messages.PublicKeyMessage.fromPackets((
            packets.PublicKeyPacket.fromParameter(nym.n,
                                                  elements.MPIElement(65537)),))
    return nym.isValid(key)


if len(sys.argv) != 3:
    print >>sys.stderr, 'usage: nym-verify.py <NYMFILE> <CAKEY>'
    sys.exit(2)

nymMessage = messages.fromRadix64(open(sys.argv[1], 'r').read())
nym = nymMessage.packets[TAG_NYM]
sig = nymMessage.packets[TAG_SIGNATURE]
if not verifySelfSignature(nym):
    print '%s: Self signature invalid' % basename(sys.argv[0])
    sys.exit(1)

keyMessage = messages.fromRadix64(open(sys.argv[2]).read())
key = keyMessage.packets[TAG_PUBKEY]

print '%s: Nym: %s' % (basename(sys.argv[0]), nym.id)
print '%s: Signature from %s ' % (
    basename(sys.argv[0]),
    sig.subpackets.get(subpackets.IssuerSubpacket.TAG))
print '%s: %s' % (basename(sys.argv[0]),
                  sig.hashedSubpackets.get(subpackets.CreationTimeSubpacket.TAG))
if keyMessage.isExpired():
    print '%s: Key is expired since %s' % (basename(sys.argv[0]),
                                           keyMessage.expirationTime())

if verifySignature(nym.rep(), nymMessage, keyMessage):
    print '%s: Signature is VALID' % (basename(sys.argv[0]))
    sys.exit(0)
else:
    print '%s: Signature is INVALID' % (basename(sys.argv[0]))
    sys.exit(1)

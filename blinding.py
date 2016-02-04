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

from OpenPGP import *
import crypto
import encoding

# ------------------------------------------------------------------------------

def _randomTime(start, end):
    random = crypto.randomInt(end.value - start.value)
    return elements.TimeElement(start.value + random)

# ------------------------------------------------------------------------------

def _prepareSignature(hashAlgorithm, sigTime, sigKeyid):
    sigPacket = packets.SignaturePacket()
    sigPacket.pubAlgorithm = elements.ScalarElement(packets.ALGORITHM_RSA)
    sigPacket.hashAlgorithm = elements.ScalarElement(hashAlgorithm)
    sigPacket.hashedSubpackets.add(
        subpackets.CreationTimeSubpacket(sigTime))
    sigPacket.subpackets.add(subpackets.IssuerSubpacket(sigKeyid))
    return sigPacket

# ------------------------------------------------------------------------------

def blind(publicKey, sigTime, data):
    keyID = publicKey.packets[TAG_PUBKEY].keyID()
    n = publicKey.packets[TAG_PUBKEY].n
    e = publicKey.packets[TAG_PUBKEY].e


    if sigTime is None:
        sigTime = _randomTime(publicKey.creationTime(),
                              publicKey.expirationTime())
    
    sigPacket = _prepareSignature(crypto.HASH_SHA256, sigTime, keyID)
    sigdata = (data + sigPacket.hashdata())
    plainhash = crypto.hash(sigdata, sigPacket.hashAlgorithm.value)
    codedhash = encoding.pkcs15(plainhash, n.bits(),
                                sigPacket.hashAlgorithm.value)
    m = elements.ScalarElement(codedhash).value
    
    while True:
        r = elements.ScalarElement(crypto.randomBytes(n.octets())).value
        if (r > 1 and
            r < n.value and
            crypto.gcd(n.value, r) == 1):
            break
        
    packet = packets.BlindMessagePacket()
    packet.m = elements.MPIElement(crypto.rsaBlind(m, r, e.value, n.value))
    return r, plainhash[0:2], sigTime, messages.BlindMessageMessage.fromPackets((packet,))

# ------------------------------------------------------------------------------

def unblind(publicKey, sigTime, r, hashTwo, blindsig):
    keyID = publicKey.packets[TAG_PUBKEY].keyID()
    n = publicKey.packets[TAG_PUBKEY].n
    e = publicKey.packets[TAG_PUBKEY].e
    
    bs = blindsig.packets[TAG_BLINDSIG].s.value
    s = crypto.rsaUnblind(r, n.value, bs)
    sigPacket = _prepareSignature(crypto.HASH_SHA256, sigTime, keyID)
    sigPacket.hashLeftTwo = hashTwo
    sigPacket.sig = elements.MPIElement(s)
    return messages.SignatureMessage().fromPackets((sigPacket,))
        
# ------------------------------------------------------------------------------

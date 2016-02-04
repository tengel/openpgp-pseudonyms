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

import crypto
import encoding
import elements
import subpackets
import packets
import messages

TAG_NYM = packets.NymPacket.TAG
TAG_PUBKEY = packets.PublicKeyPacket.TAG
TAG_SECKEY = packets.SecretKeyPacket.TAG
TAG_SIGNATURE = packets.SignaturePacket.TAG
TAG_USERID = packets.UserIDPacket.TAG
TAG_BLINDMSG = packets.BlindMessagePacket.TAG
TAG_BLINDSIG = packets.BlindSignaturePacket.TAG

# ------------------------------------------------------------------------------

def verifySignature(m, signature, publicKey):
    """
    Verify a type 0 signature over m

    @param m: binary message
    @type m: string
    @param signature: The OpenPGP signature over m.
    @type signature: SignatureMessage
    @param publicKey: The public key of the signer.
    @type publicKey: PublicKeyMessage
    @return: Returns true if the signature is valid.
    """

    data = (m + signature.packets[TAG_SIGNATURE].hashdata())
    plainhash = crypto.hash(
        data,
        signature.packets[TAG_SIGNATURE].hashAlgorithm.value)
    if signature.packets[TAG_SIGNATURE].hashLeftTwo != plainhash[0:2]:
        return False

    codedhash = encoding.pkcs15(
        plainhash,
        publicKey.packets[TAG_PUBKEY].n.bits(),
        signature.packets[TAG_SIGNATURE].hashAlgorithm.value)
    codedhashInt = elements.ScalarElement(codedhash).value
    
    rsaN = publicKey.packets[TAG_PUBKEY].n.value
    rsaE = publicKey.packets[TAG_PUBKEY].e.value
    return crypto.rsaVerify(signature.packets[TAG_SIGNATURE].sig.value,
                            codedhashInt, rsaE, rsaN)

# ------------------------------------------------------------------------------

def computeSignature(m, secretKey):
    """
    Compute a type 0 signature.

    @param m: Message of binary data to sign.
    @type m: string
    @param secretKey: Key used for signature.
    @type secretKey: SecretKeyMessage
    @return: An OpenPGP signature message.
    """
    sigPacket = packets.SignaturePacket()
    sigPacket.version = elements.ScalarElement(4)
    sigPacket.signatureType = elements.ScalarElement(0)
    sigPacket.pubAlgorithm = elements.ScalarElement(1)
    sigPacket.hashAlgorithm = elements.ScalarElement(crypto.HASH_SHA256)
    sigPacket.hashedSubpackets.add(subpackets.CreationTimeSubpacket(
            elements.TimeElement.now()))
    sigPacket.subpackets.add(
        subpackets.IssuerSubpacket(secretKey.packets[TAG_SECKEY].keyID()))
    data = (m + sigPacket.hashdata())
    plainhash = crypto.hash(data, sigPacket.hashAlgorithm.value)
    sigPacket.hashLeftTwo = plainhash[0:2]

    codedhash = encoding.pkcs15(
        plainhash,
        secretKey.packets[TAG_SECKEY].n.bits(),
        sigPacket.hashAlgorithm.value)
    codedhashInt = elements.ScalarElement(codedhash).value

    rsaN = secretKey.packets[TAG_SECKEY].n.value
    rsaD = secretKey.packets[TAG_SECKEY].d.value
    s = crypto.rsaSign(codedhashInt, rsaD, rsaN)
    sigPacket.sig = elements.MPIElement(s)

    pgpMessage = messages.SignatureMessage.fromPackets((sigPacket,))
    return pgpMessage


# ------------------------------------------------------------------------------

def generateKey(bits):
    key = crypto.rsaGenerate(bits)
    pubKey = packets.PublicKeyPacket.fromParameter(elements.MPIElement(key[0]),
                                                   elements.MPIElement(key[1]))
    secKey = packets.SecretKeyPacket.fromParameter(elements.MPIElement(key[0]),
                                                   elements.MPIElement(key[1]),
                                                   elements.MPIElement(key[2]),
                                                   elements.MPIElement(key[3]),
                                                   elements.MPIElement(key[4]),
                                                   elements.MPIElement(key[5]))
    return (messages.PublicKeyMessage.fromPackets((pubKey,)),
            messages.SecretKeyMessage.fromPackets((secKey,)))

# ------------------------------------------------------------------------------

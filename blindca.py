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

class Config:
    def __init__(self):
        self.secretKey = None
        self.publicKey = None
        self.passwordCallback = None

class BlindCA:
    """
    The BlindCA signs the content of a BlindMessage. This is done without doing
    further hashing or padding.
    """

    def __init__(self, config):
        """
        Initialize the CA with a Config object.

        @param config: Configuration of BlindCA
        """
        if (config is None or
            config.secretKey is None or
            len(config.secretKey) == 0):
            raise Exception('invalid configuration')
        self.secretKey = messages.fromRadix64(open(config.secretKey, 'r').read(),
                                              config.passwordCallback)
        if config.publicKey is not None:
            self.publicKey = messages.fromRadix64(open(config.publicKey).read())

    def sign(self, bm):
        """
        Create the signature.
        
        @param bm: The message to be signed.
        @type bm: openpgp.BlindMessageMessage.
        @return: The signature as a BlindSigntureMessage.
        """
        packet = packets.BlindSignaturePacket()
        packet.s = elements.MPIElement(crypto.rsaSign(
            bm.packets[TAG_BLINDMSG].m.value,
            self.secretKey.packets[TAG_SECKEY].d.value,
            self.secretKey.packets[TAG_SECKEY].n.value))
        message = messages.BlindSignatureMessage().fromPackets((packet,))
        return message

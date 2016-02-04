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

import OpenPGP
import blinding
import socket
import sys
import ssl
import re
import httplib

class Config:
    def __init__(self):
        self.publicKey = ''
        self.sslCert = ''
        self.idHost = 'localhost'
        self.idPort = 9999
        self.keyHost = 'localhost'
        self.keyPort = 11371

class IDClient:
    def __init__(self, config):
        self.config = config
        self.loadKey(config.publicKey)
        self.sslContext = ssl.create_default_context()
        self.sslContext.load_verify_locations(self.config.sslCert)
        self.sslContext.check_hostname = False

    def loadKey(self, filename):
        try:
            self.caKey = OpenPGP.messages.fromRadix64(open(filename, 'r').read())
        except:
            self.caKey = None

    def _sendRequest(self, auth, requestData=''):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sslsocket = ssl.wrap_socket(s, ca_certs = self.config.sslCert,
                                    cert_reqs=ssl.CERT_REQUIRED)
        try:
            sslsocket.connect((self.config.idHost, self.config.idPort))
        except ssl.SSLError, e:
            print 'IDClient: Exception: ', e
            raise e
        msg = ('Authorization: %s\r\nLength: %d\r\n\r\n%s\r\n' %
               (auth.strip(), len(requestData), requestData))
        sent = 0
        while sent < len(msg):
            sent += sslsocket.send(msg[sent:])
        received = ''
        while True:
            s = sslsocket.recv(1024)
            if len(s) == 0:
                break
            received += s
        sslsocket.shutdown(socket.SHUT_RDWR)
        sslsocket.close()
        try:
            match = re.match('IDServer:\s*(.+)\r\n(.*)', received,
                             re.MULTILINE | re.DOTALL)
            result = match.group(1).strip().lower()
            receivedData = match.group(2).strip()
        except:
            return None, 'invalid response from server'
        if result != 'ok':
            return None, result
        else:
            return receivedData, result

    def acquireSignature(self, nym, auth):
        if self.caKey is None:
            raise Exception('no public key')

        r, hashTwo, sigTime, blinded = blinding.blind(self.caKey, None, nym)

        data, result = self._sendRequest(auth, blinded.rep())
        if data is None or result != 'ok':
            return None, result

        blindSig = OpenPGP.messages.fromRadix64(data)
        sig = blinding.unblind(self.caKey, sigTime, r, hashTwo, blindSig)
        return sig, result

    def fetchKey(self):
        connection = httplib.HTTPSConnection(self.config.keyHost,
                                             self.config.keyPort,
                                             context=self.sslContext)
        connection.request('GET', '/pks/lookup?op=get')
        response = connection.getresponse()
        if response.status != 200:
            return None
        return response.read()

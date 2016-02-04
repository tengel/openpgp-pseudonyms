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
sys.path.append('..')

import unittest
import threading
import httplib
import tempfile
import ssl

import idclient
import OpenPGP
import idserver

# ------------------------------------------------------------------------------

class ServerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        serverConfig = idserver.Config('testdata/idserver_tests.conf')
        self.server = idserver.IDServer(serverConfig)
        self.server.run()

    def shutdown(self):
        self.server.shutdown()

# ------------------------------------------------------------------------------

class TestIDServer(unittest.TestCase):
    pubkey = ('-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'
              'wsE+BBMBAgAoBQJOz617AhsDBQkDwmcABgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIX\n'
              'gAAKCRBAdRtK3tGg5w/SB/49Fqz9uBAUU4nGPwZ64a04MFmjYnMKjLyUzYnOr1lY\n'
              'KnWTOHHUf2Bmkg8sphHp+CDvUIk8cOgcXnTh5tpcT9DDqZ31ojRl43s7YjGrcuo8\n'
              'RN3QlEYb3wiruawGTkUZAeRHptw/JFNYJGvpzR9W6ykGFaOva5x5+hvyghgitts7\n'
              'GZtwYzPdoGMTQnmBwQ5AS21SIzceMtqKr4sDL0aZWworcY4wpzJMyIwT0EERWRqa\n'
              'AgPtDN1mY46zg1h5QMowFmYC8V6kVQhZk2uRUv+hb8V4Rodg2TUgyTj0CLrPDTBg\n'
              'Iun+ZOKcLpNoRDIZjtg4oGL6Mmg2kQtUt1btDVR1frZtzRdGb29iYXIgPGZvb2Jh\n'
              'ckBiYXIuY29tPsbBDQROz617AQgAzIQoP6sCsbmHtOtyJxzjnMe8iPQ5vPkTq0GQ\n'
              'qlspPr3dJzTX8zTKT21n/rqM3kDJFqcAA8QwxkR6sGzYS6sFIiqPI13wq9UlSIZy\n'
              'Zb00JNjIKYk8Fylvh0vHTvaFIHgEgU9QOlXx6IVkwm2MtMSkISqHnUkfV/Y4exvY\n'
              'XScAE4mvXAZtJhdnn2MaebRyTSUboCmxHGIi+c+N098RMnkP734wVc7b3KT5lmL0\n'
              'ZLi+hlBc1l0Fc9JpvgtNAoRpencGlMGoY/GZGVxUGhmm/7WehK483U1XiXUyBgtJ\n'
              'K0dyLz/Y1cP1sHlLiOqCzyccs9jeeMQn8OVMQmik+jEzTQYFuwARAQAB\n'
              '=Naub\n'
              '-----END PGP PUBLIC KEY BLOCK-----\n\r\n')

    def setUp(self):
        self.serverThread = ServerThread()
        self.serverThread.start()
        while True:
            try:
                if self.serverThread.server.idThread.running:
                    break
            except:
                pass
        self.caKey = OpenPGP.messages.fromRadix64(
            open('testdata/foobar-bar.com_public_2048.txt', 'r').read())
        self.clientConfig = idclient.Config()
        self.clientConfig.publicKey = 'testdata/foobar-bar.com_public_2048.txt'
        self.clientConfig.sslCert = 'testdata/ssl.crt'
        self.client = idclient.IDClient(self.clientConfig)

    def tearDown(self):
        self.serverThread.shutdown()
        self.serverThread.join()

    def testUsers(self):
        cfgFile = tempfile.NamedTemporaryFile(mode='w')
        cfgFile.write('jdoe:secret:\n')
        cfgFile.write('mmustermann:geheim:abc123\n')
        cfgFile.flush()

        users = idserver.Users(cfgFile.name)
        self.assertTrue(users.isAuthorized('jdoe', 'secret'))
        self.assertTrue(users.isAuthorized('mmustermann', 'geheim'))
        self.assertFalse(users.isAuthorized('invalid', 'secret'))
        self.assertFalse(users.isAuthorized('jdoe', 'invalid'))
        self.assertTrue(users.hasSigned('mmustermann', 'abc123'))
        self.assertFalse(users.hasSigned('mmustermann', 'notsigned'))
        self.assertFalse(users.hasSigned('jdoe', 'notsigned'))

    def testSign(self):
        m = 'Foobar'
        auth = 'jdoe:secret'.encode('base64')
        s, result = self.client.acquireSignature(m, auth)
        self.assertEqual(result, 'ok')
        self.assertTrue(OpenPGP.verifySignature(m, s, self.caKey))


    def testKey(self):
        sslContext = ssl.create_default_context()
        sslContext.load_verify_locations(self.clientConfig.sslCert)
        sslContext.check_hostname = False
        conn = httplib.HTTPSConnection('localhost', 11371, context=sslContext)
        conn.request('GET', '/pks/lookup?op=get')
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), self.pubkey)

    def testFetchKey(self):
        self.assertEqual(self.client.fetchKey(), self.pubkey)

    def testErrors(self):
        sig, result = self.client.acquireSignature('Foobar', 'invalid')
        self.assertEqual(sig, None)
        self.assertEqual(result, 'invalid request')
        sig, result = self.client.acquireSignature('Foobar',
                                                  'in:valid'.encode('base64'))
        self.assertEqual(sig, None)
        self.assertEqual(result, 'not authorized')

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

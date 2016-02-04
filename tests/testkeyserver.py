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
import ssl

import idclient
import OpenPGP
import keyserver

# ------------------------------------------------------------------------------

class ServerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        serverConfig = keyserver.Config()
        serverConfig.key = 'foobar'
        serverConfig.sslCert = 'testdata/ssl.crt'
        serverConfig.sslKey = 'testdata/ssl.key'
        self.server = keyserver.KeyServer(serverConfig)
        self.server.run()

    def shutdown(self):
        self.server.shutdown()

# ------------------------------------------------------------------------------

class TestKeyServer(unittest.TestCase):
    def setUp(self):
        self.serverThread = ServerThread()
        self.serverThread.start()
        while True:
            try:
                if self.serverThread.server.running:
                    break
            except:
                pass

    def tearDown(self):
        self.serverThread.shutdown()
        self.serverThread.join()

    def testGetKey(self):
        sslContext = ssl.create_default_context()
        sslContext.load_verify_locations('testdata/ssl.crt')
        sslContext.check_hostname = False
        conn = httplib.HTTPSConnection('localhost', 11371,
                                       context = sslContext)
        conn.request('GET', '/pks/lookup?op=get')
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), 'foobar\r\n')

        conn.request('GET', '/invalid')
        self.assertEqual(conn.getresponse().status, 400)

        conn.request('GET', '/pks/lookup?op=index')
        self.assertEqual(conn.getresponse().status, 501)

        conn.request('GET', '/pks/lookup?op=vindex')
        self.assertEqual(conn.getresponse().status, 501)

        conn.request('GET', '/pks/lookup?op=invalid')
        self.assertEqual(conn.getresponse().status, 400)

        conn.close()

# ------------------------------------------------------------------------------

if __name__ == '__main__':
        unittest.main()

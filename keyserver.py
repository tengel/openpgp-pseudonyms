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

import BaseHTTPServer
import os
import urlparse
import ssl

config = None

# ------------------------------------------------------------------------------

class KeyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        if not '?' in self.path:
            self.send_error(400)
            return
        path, varstring = self.path.split('?', 1)
        if path != '/pks/lookup':
            self.send_error(400)
            return
        
        varmap = urlparse.parse_qs(varstring)
        if not varmap.has_key('op'):
            self.send_error(400)
            return
        if varmap['op'][0] == 'index':
            self.send_error(501)
            return
        if varmap['op'][0] == 'vindex':
            self.send_error(501)
            return
        if varmap['op'][0] != 'get':
            self.send_error(400)
            return        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(config.key + '\r\n')

# ------------------------------------------------------------------------------

class Config:
    def __init__(self):
        self.host = 'localhost'
        self.port = 11371
        self.key  = ''
        self.sslCert = ''
        self.sslKey = ''

# ------------------------------------------------------------------------------

class KeyServer:
    def __init__(self, cfg):
        global config
        config = cfg

    def run(self):
        self.running = True
        BaseHTTPServer.HTTPServer.allow_reuse_address = True
        self.httpd = BaseHTTPServer.HTTPServer((config.host, config.port),
                                               KeyHandler)
        self.httpd.socket = ssl.wrap_socket(self.httpd.socket, server_side=True,
                                            certfile = config.sslCert,
                                            keyfile = config.sslKey)
        self.httpd.serve_forever()
        self.running = False

    def shutdown(self):
        self.httpd.shutdown()
        del self.httpd
        while self.running:
            pass
        
# ------------------------------------------------------------------------------

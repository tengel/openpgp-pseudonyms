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
import socket
import blindca
import OpenPGP
import re
import ssl
import threading
import keyserver
import os
import time

ca = None
users = None
config = None

# ------------------------------------------------------------------------------

def enterPassword():
    print 'Passphrase needed for key %s' % config.cfg[config.SECRETKEY]
    return raw_input('password: ')

# ------------------------------------------------------------------------------

class Users:
    def __init__(self, file):
        self.usersFile = file
        self.users = {}
        f = open(file)
        for s in f:
            user, passwd, keyid = s.strip().split(':')
            self.users[user] = [passwd, keyid]

    def __del__(self):
        f = open(self.usersFile, 'w')
        for user in self.users:
            f.write('%s:%s:%s\n' % (user,
                                    self.users[user][0],
                                    self.users[user][1]))
        f.close()

    def isAuthorized(self, user, password):
        if not user in self.users:
            return False
        if self.users[user][0] == password:
            return True
        else:
            return False

    def hasSigned(self, user, keyid):
        if not user in self.users:
            raise Exception('user not found')
        if self.users[user][1] == keyid:
            return True
        else:
            return False

    def setKeyId(self, user, keyid):
        if not user in self.users:
            raise Exception('user not found')
        self.users[user][1] = keyid

# ------------------------------------------------------------------------------

class Config:
    HOST = 'host'
    IDPORT = 'idport'
    KEYPORT = 'keyport'
    SECRETKEY = 'secretkey'
    PUBLICKEY = 'publickey'
    USERSFILE = 'usersfile'
    TLSKEY = 'tlskey'
    TLSCERT = 'tlscert'
    
    def __init__(self, cfgFile):
        self.cfg = {self.HOST: 'localhost',
                    self.IDPORT: 9999,
                    self.KEYPORT: 11371,
                    self.SECRETKEY: '',
                    self.PUBLICKEY: '',
                    self.USERSFILE: '',
                    self.TLSKEY: '',
                    self.TLSCERT: ''}
                    
        try:
            f = open(os.path.expanduser(cfgFile), 'r')
            for s in f:
                if s.strip().startswith('#'):
                    continue
                name, value = s.split('=')
                if self.cfg.has_key(name.strip().lower()):
                    self.cfg[name.strip().lower()] = value.strip()
                else:
                    print >>sys.stderr, 'invalid keyword in config file'
            self.cfg[self.SECRETKEY] = os.path.expanduser(self.cfg[self.SECRETKEY])
            self.cfg[self.PUBLICKEY] = os.path.expanduser(self.cfg[self.PUBLICKEY])
            self.cfg[self.USERSFILE] = os.path.expanduser(self.cfg[self.USERSFILE])
            self.cfg[self.TLSKEY] = os.path.expanduser(self.cfg[self.TLSKEY])
            self.cfg[self.TLSCERT] = os.path.expanduser(self.cfg[self.TLSCERT])
            self.cfg[self.IDPORT] = int(self.cfg[self.IDPORT])
            self.cfg[self.KEYPORT] = int(self.cfg[self.KEYPORT])
        except Exception, e:
            print >>sys.stderr, 'error in configfile: ', e
            raise e


# ------------------------------------------------------------------------------

class IDServerThread(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config
        self.listensocket = socket.socket()
        self.listensocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listensocket.bind((self.config.cfg[self.config.HOST],
                                self.config.cfg[self.config.IDPORT]))
        self.listensocket.listen(5)

    def run(self):
        print 'IDServer: run'
        self.running = True
        while self.running:
            try:
                newsocket, fromaddr = self.listensocket.accept()
            except Exception, e:
                if self.running == False:
                    return
                print 'IDServer: accept: Exception: ', e
                continue
            print 'IDServer: connection from ', fromaddr
            try:
                sslsocket = ssl.wrap_socket(
                    newsocket, server_side=True,
                    certfile = self.config.cfg[self.config.TLSCERT],
                    keyfile = self.config.cfg[self.config.TLSKEY])
            except ssl.SSLError, e:
                print 'IDServer: wrap_socket: Exception: ', e
                newsocket.shutdown(socket.SHUT_RDWR)
                newsocket.close()
                continue
            handleConnection(sslsocket)
            sslsocket.shutdown(socket.SHUT_RDWR)
            sslsocket.close()

    def shutdown(self):
        print 'IDServer: shutdown'
        self.running = False
        self.listensocket.shutdown(socket.SHUT_RDWR)
        self.listensocket.close()
        
# ------------------------------------------------------------------------------

class KeyServerThread(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.config = config

    def run(self):
        self.server = keyserver.KeyServer(self.config)
        self.server.run()

    def shutdown(self):
        self.server.shutdown()
        
# ------------------------------------------------------------------------------

class IDServer:
    def __init__(self, config):
        global ca
        global users
        self.config = config
        caConfig = blindca.Config()
        caConfig.secretKey = self.config.cfg[self.config.SECRETKEY]
        caConfig.publicKey = self.config.cfg[self.config.PUBLICKEY]
        caConfig.passwordCallback = enterPassword
        ca = blindca.BlindCA(caConfig)
        users = Users(self.config.cfg[self.config.USERSFILE])

        self.idThread = IDServerThread(self.config)
        keyServerConfig = keyserver.Config()
        keyServerConfig.key = ca.publicKey.rep()
        keyServerConfig.sslKey = self.config.cfg[self.config.TLSKEY]
        keyServerConfig.sslCert = self.config.cfg[self.config.TLSCERT]
        self.keyThread = KeyServerThread(keyServerConfig)

    def run(self):
        self.keyThread.start()
        self.idThread.start()

    def shutdown(self):
        self.idThread.shutdown()
        self.keyThread.shutdown()
        self.idThread.join()
        self.keyThread.join()

# ------------------------------------------------------------------------------

def handleConnection(socket):
    receivedBytes = 0
    received = socket.recv(1024)
    try:
        match=re.match(
            'Authorization:\s*(\S+)\r\nLength:\s*(\d+)\r\n(.*)',
            received, re.MULTILINE | re.DOTALL)
        user, password = match.group(1).decode('base64').split(':')
        length = int(match.group(2))
        data = match.group(3)
    except:
        print 'IDServer: invalid request'
        send(socket, 'IDServer: invalid request\r\n')
        return
    while len(data) < length:
        data += socket.recv(1024)

    print 'IDServer: user:%s password:%s' % (user, password)
    if not users.isAuthorized(user, password):
        print 'IDServer: not authorized'
        send(socket, 'IDServer: not authorized\r\n')
        return
    try:
        keyid = ca.secretKey.packets[OpenPGP.TAG_SECKEY].keyID().encode('hex')
        if users.hasSigned(user, keyid):
            print 'IDServer: user has already signed'
            send(socket, 'IDServer: user has already signed\r\n')
            return
        blindMessage = OpenPGP.messages.fromRadix64(data.strip())
        blindSig = ca.sign(blindMessage)
        users.setKeyId(user, keyid)
        send(socket, 'IDServer: ok\r\n' + blindSig.rep())
    except Exception, e:
        print 'IDServer: ', e
        send(socket, 'IDServer: signature failed')

# ------------------------------------------------------------------------------

def send(socket, msg):
    sent = 0
    while sent < len(msg):
        sent += socket.send(msg[sent:])

# ------------------------------------------------------------------------------

if __name__ == "__main__":
    cfgFile = '/etc/idserver.conf'
    if len(sys.argv) > 1:
        cfgFile = sys.argv[1]
    config = Config(cfgFile)
    server = IDServer(config)
    server.run()
    try:
        while True:
            time.sleep(1)
    except:
        server.shutdown()
        users.__del__()

# ------------------------------------------------------------------------------

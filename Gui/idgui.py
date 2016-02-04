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

from Tkinter import *
import tkMessageBox
import tkSimpleDialog
import os

from authwidget import *
from nymwidget import *
from sigwidget import *
import idclient

# ------------------------------------------------------------------------------

class IDGui():

    def __init__(self, config):
        self.config = config
        clientConfig = idclient.Config()
        clientConfig.publicKey = self.config.cfg[Config.SERVERKEY]
        clientConfig.sslCert = self.config.cfg[Config.SSLCERT]
        clientConfig.idHost = self.config.cfg[Config.SERVER]
        clientConfig.idPort = int(self.config.cfg[Config.SERVERPORT])
        clientConfig.keyHost = self.config.cfg[Config.SERVER]
        self.client = idclient.IDClient(clientConfig)
        self.top = Tk()
        self.authWidget = AuthWidget(self.top)
        self.authWidget.pack(expand=1, fill=BOTH)
        self.nymWidget = NymWidget(config, self.top)
        self.nymWidget.pack(expand=1, fill=BOTH)
        self.sigWidget = SigWidget(config, self.top,
                                   commandSign=self.actionSign,
                                   commandKey=self.actionKey)
        self.sigWidget.pack(expand=1, fill=BOTH)
        self.quitButton = Button(self.top, text='Exit', command=self.actionQuit)
        self.quitButton.pack()

        self.top.mainloop()

    def actionQuit(self):
        self.top.destroy()

    def actionSign(self):
        credentials = self.authWidget.credentials()
        nym = self.nymWidget.getNym()
        if nym is None:
            return
        keySize = self.config.serverKey.packets[OpenPGP.TAG_PUBKEY].n.bits()
        try:
            caSignature, result = self.client.acquireSignature(
                nym.packets[OpenPGP.TAG_NYM].rep(), credentials)
        except Exception, e:
            tkMessageBox.showerror('Error',
                                   'Failed to fetch signature: ' + e.__str__())
            return
        if caSignature is None or result != 'ok':
            tkMessageBox.showerror('Error',
                                   'Failed to fetch signature: ' + result)
            return
        signedNym = OpenPGP.messages.Message.fromPackets((
                caSignature.packets[OpenPGP.TAG_SIGNATURE],
                nym.packets[OpenPGP.TAG_NYM]))
        self.sigWidget.setText(signedNym.rep())
        #print >>sys.stderr, signedNym
        open(self.config.cfg[Config.NYM], 'w').write(signedNym.rep())

    def actionKey(self):
        try:
            key = self.client.fetchKey()
        except Exception, e:
            tkMessageBox.showerror('Error',
                                   'Failed to fetch key: ' + e.__str__())
            return
        if key is None or key == '':
            tkMessageBox.showerror('Error',
                                   'Failed to fetch key: ' + result)
            return
        open(self.config.cfg[Config.SERVERKEY], 'w').write(key)
        self.config = Config(self.config.cfgFile)
        self.client.loadKey(self.config.cfg[Config.SERVERKEY])
        self.sigWidget.setServerKey(self.config)

# ------------------------------------------------------------------------------

class Config:
    SERVER = 'server'
    SERVERPORT = 'serverport'
    KEYSERVERPORT = 'keyserverport'
    SERVERKEY = 'serverkey'
    SSLCERT = 'tlscertificate'
    NYM = 'nymfile'
    SECRETKEY = 'secretkey'
    PUBLICKEY = 'publickey'

    def __init__(self, cfgFile):
        self.cfgFile = cfgFile
        self.cfg = {self.SERVER: 'localhost',
                    self.SERVERPORT: 9999,
                    self.KEYSERVERPORT: 11371,
                    self.SERVERKEY: '~/idserver_pubkey.txt',
                    self.NYM:'~/idgui_nym.txt',
                    self.SECRETKEY: '~/idgui_secretkey.txt',
                    self.PUBLICKEY: '~/idgui_publickey.txt',
                    self.SSLCERT: ''}
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
            self.cfg[self.SERVERKEY]=os.path.expanduser(self.cfg[self.SERVERKEY])
            self.cfg[self.NYM] = os.path.expanduser(self.cfg[self.NYM])
            self.cfg[self.SECRETKEY]=os.path.expanduser(self.cfg[self.SECRETKEY])
            self.cfg[self.PUBLICKEY]=os.path.expanduser(self.cfg[self.PUBLICKEY])
            self.cfg[self.SSLCERT] = os.path.expanduser(self.cfg[self.SSLCERT])
        except:
            pass

        try:
            self.serverKey = OpenPGP.messages.fromRadix64(
                open(self.cfg[self.SERVERKEY]).read())
        except:
            self.serverKey = None
        try:
            self.nym = OpenPGP.messages.fromRadix64(
                open(self.cfg[self.NYM]).read())
        except:
            self.nym = None
        self.secretKey = None
        try:
            self.publicKey = OpenPGP.messages.fromRadix64(
                open(self.cfg[self.PUBLICKEY]).read())
        except:
            self.publicKey = None

# ------------------------------------------------------------------------------
        
if __name__ == '__main__':
    cfgFile = '~/idgui.conf'
    if len(sys.argv) > 1:
        cfgFile = sys.argv[1]
    cfg = Config(cfgFile)
    IDGui(cfg)

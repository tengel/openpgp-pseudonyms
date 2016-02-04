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
import OpenPGP
from idgui import *

class NymWidget(LabelFrame):

    def __init__(self, config, master=None, **kw):
        LabelFrame.__init__(self, master, text='Pseudonym', relief=GROOVE,
                            borderwidth=2)
        self.config = config
        f1 = Frame(self)
        f1.pack(expand=1, fill=BOTH)
        f2 = Frame(self)
        f2.pack(expand=1, fill=BOTH)
        Label(f1, text='Pseudonym:', width=10, anchor=W).pack(side=LEFT)
        self.idEntry = Entry(f1, width=20)
        self.idEntry.pack(side=RIGHT, fill=X, expand=1)
        Label(f2, text='Key ID:', width=10, anchor=W).pack(side=LEFT)
        self.keyVar = StringVar()
        Entry(f2, textvariable=self.keyVar, width=20,
              state='readonly').pack(side=LEFT, fill=X, expand=1)
        Button(f2, text='Generate new Key',
               command=self.actionGenerate).pack(side=LEFT)

        self.nym = config.nym
        self.pubKey = config.publicKey
        self.secKey = config.secretKey
        if self.nym is not None:
            self.idEntry.insert(0, self.nym.packets[OpenPGP.TAG_NYM].id)
            self.keyVar.set(self.nym.packets[OpenPGP.TAG_NYM].keyID().encode('hex'))
        
    def actionGenerate(self):
        self.pubKey, self.secKey = OpenPGP.generateKey(2048)
        self.nym = OpenPGP.messages.Message.fromPackets((
                OpenPGP.packets.NymPacket.fromParameter(
                    self.idEntry.get(),
                    self.pubKey.packets[OpenPGP.TAG_PUBKEY].n),))
        self.idEntry.delete(0, END)
        self.idEntry.insert(0, self.nym.packets[OpenPGP.TAG_NYM].id)
        self.keyVar.set(self.nym.packets[OpenPGP.TAG_NYM].keyID().encode('hex'))
        open(self.config.cfg[Config.PUBLICKEY], 'w').write(self.pubKey.rep())
        passphrase = tkSimpleDialog.askstring('idgui.py',
                                              'Enter passphrase for secret key:')
        open(self.config.cfg[Config.SECRETKEY], 'w').write(
            self.secKey.rep(passphrase))


    def getNym(self):
        if self.secKey is None:
            try:
                self.secKey = OpenPGP.messages.fromRadix64(
                    open(self.config.cfg[Config.SECRETKEY]).read(),
                    passphraseCallback)
            except Exception, e:
                tkMessageBox.showerror('Error',
                                       'Failed to read key: ' + e.__str__())
                return None
        self.nym.packets[OpenPGP.TAG_NYM].computeSignature(self.secKey)
        return self.nym

# ------------------------------------------------------------------------------

def passphraseCallback():
    return tkSimpleDialog.askstring('idgui.py',
                                   'Enter passphrase for secret key:')

# ------------------------------------------------------------------------------

if __name__ == '__main__':
    root = Tk()
    NymWidget(root).pack()
    root.mainloop()



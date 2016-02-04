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
from OpenPGP import *

class SigWidget(LabelFrame):

    def __init__(self, config, master=None, **kw):
        LabelFrame.__init__(self, master, text='Signature', relief=GROOVE,
                            borderwidth=2)
        f1 = Frame(self)
        f1.pack(expand=1, fill=BOTH)
        f2 = Frame(self)
        f2.pack(expand=1, fill=BOTH)
        f3 = Frame(self)
        f3.pack(expand=1, fill=BOTH)
        Label(f1, text='Public Key:', width=10, anchor=W).pack(side=LEFT)
        self.keyEntry = Entry(f1, width=20, state="readonly")
        self.keyEntry.pack(side=LEFT, fill=X, expand=1)
        Label(f2, text='Key ID:', width=10, anchor=W).pack(side=LEFT)
        self.keyIdEntry = Entry(f2, width=20, state="readonly")
        self.keyIdEntry.pack(side=LEFT, fill=X, expand=1)
        Label(f3, text='Expires:', width=10, anchor=W).pack(side=LEFT)
        self.expiresEntry = Entry(f3, width=20, state="readonly")
        self.expiresEntry.pack(side=LEFT, fill=X, expand=1)
        f4 = Frame(self)
        f4.pack(expand=1, fill=BOTH)
        Label(f4, width=10).pack(side=LEFT)
        Button(f4, text='Fetch Public-Key', width=12,
               command=kw['commandKey']).pack(side=LEFT)
        Button(f4, text='Get Signature', width=12,
               command=kw['commandSign']).pack(side=LEFT)
        self.text = Text(self, width=50, height=16, state=DISABLED)
        self.text.pack(side=BOTTOM, fill=BOTH, expand=1)
        
        if config.serverKey is not None:
            self.setServerKey(config)
        if config.nym is not None:
            self.setText(config.nym.rep())

    def setServerKey(self, config):
        key = config.cfg[config.SERVERKEY]
        expires = config.serverKey.expirationTime().__str__()
        if config.serverKey.isExpired():
            expires += ' (expired)'
        keyId = config.serverKey.packets[TAG_PUBKEY].keyID().encode('hex')
        self.keyEntry.config(state=NORMAL)
        self.keyEntry.delete(0, END)
        self.keyEntry.insert(0, key)
        self.keyEntry.config(state='readonly')
        self.keyIdEntry.config(state=NORMAL)
        self.keyIdEntry.delete(0, END)
        self.keyIdEntry.insert(0, keyId)
        self.keyIdEntry.config(state='readonly')
        self.expiresEntry.config(state=NORMAL)
        self.expiresEntry.delete(0, END)
        self.expiresEntry.insert(0, expires)
        self.expiresEntry.config(state='readonly')

    def setText(self, text):
        self.text.config(state=NORMAL)
        self.text.delete(1.0, END)
        self.text.insert(END, text)
        self.text.config(state=DISABLED)


if __name__ == '__main__':
    root = Tk()
    SigWidget(root).pack()
    root.mainloop()



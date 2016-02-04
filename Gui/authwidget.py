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

from Tkinter import *

class AuthWidget(LabelFrame):

    def __init__(self, master=None, **kw):
        LabelFrame.__init__(self, master, text='Authentication', relief=GROOVE,
                            borderwidth=2)
        f1 = Frame(self)
        f1.pack(expand=1, fill=BOTH)
        f2 = Frame(self)
        f2.pack(expand=1, fill=BOTH)
        Label(f1, text='Username:', width=10, anchor=W).pack(side=LEFT)
        self.userEntry = Entry(f1, width=20)
        self.userEntry.pack(side=LEFT, fill=X, expand=1)
        Label(f2, text='Password:', width=10, anchor=W).pack(side=LEFT)
        self.passEntry = Entry(f2, width=20, show='*')
        self.passEntry.pack(side=LEFT, fill=X, expand=1)

    def credentials(self):
        auth = self.userEntry.get().strip() + ':' + self.passEntry.get().strip()
        return auth.encode('base64')
        
if __name__ == '__main__':
    root = Tk()
    AuthWidget(root).pack()
    root.mainloop()



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

import OpenPGP

# ------------------------------------------------------------------------------

def enterPassword():
    print 'Passphrase needed for secret key'
    return raw_input('password: ')

# ------------------------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print  ('openpgpdump.py\n'
                'Print contents of a radix64 OpenPGP message.\n'
                'usage: openpgpdump.py FILE')
        sys.exit(2)
    f = open(sys.argv[1], 'r')
    if f is None:
        print '%s: %s: unable to read file' % (sys.argv[0], sys.argv[1])
        sys.exit(1)
    m = OpenPGP.messages.fromRadix64(f.read(), enterPassword)
    print m

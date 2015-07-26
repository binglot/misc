#-------------------------------------------------------------------------------
# Name:        ssh_fingerprint_extractor.py
# Purpose:     To search a blob of data for a SSH public key and generate the
#              fingerprint. Don't feed it a PCAP file, instead export the TCP
#              session (Tshark/Wireshark) and provide that.
#
# Author:      Bartosz Inglot
# Created:     2015-07-26
#
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import sys, os, struct, hashlib, mmap

# Src: cisco-calculate-ssh-fingerprint.py by Didier Stevens
def SplitPerXCharacters(string, count):
    return [string[iter:iter+count] for iter in range(0, len(string), count)]

def read_key(mm, offset):
    mm.seek(offset - 4)
    size = struct.unpack_from('>I', mm.read(4))[0]
    return mm.read(size)

def calc_fingerprint(data):
    return hashlib.md5(data).hexdigest()

def main(args):
    if len(args) != 2:
        print('Usage: %s FILE.BIN')
        print('Tip: Extract the TCP stream with Wireshark and feed the file.')
        exit(1)
    with open(args[1], 'r+b') as f:
        mm = mmap.mmap(f.fileno(), 0)
        found = False
        while(True):
            offset = mm.find('\x00\x00\x00\x07ssh-rsa') # more robust than string
            if offset < 0:
                if not found:
                    print('[-] Did not find the public key')
                break
            found = True
            key = read_key(mm, offset)
            fingerprint = calc_fingerprint(key)
            print('Offset: %s' % offset)
            print(' Fingerprint: %s' % ':'.join(SplitPerXCharacters(fingerprint, 2)))


if __name__ == '__main__':
    main(sys.argv)

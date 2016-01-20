#-------------------------------------------------------------------------------
# Name:        at_jobs_carver.py
# Purpose:     To carve out Windows schedule task (.JOB) files from BLOBs of data,
#              such as a memory dump or a page file. The script relies on two
#              observations:
#                1) AT job files have the same comment,
#                2) the value for Error Code field is always 0x00000000, while
#                   Status field is one of three values in format 0x0004130?.
#
# Author:      Bartosz Inglot
#
# Created:     2015-09-03
# Licence:     GNU General Public License v2.0 (GPL-2.0)
#-------------------------------------------------------------------------------

import sys, os, mmap, re

# Hard-coded values that the code relies on:
JOB_COMMENT = 'Created by NetScheduleJobAdd.'
FIXED_SECTION_LEN = 68
EXIT_CODE_OFFSET = 40
EXIT_CODE_AND_STATUS_REGEX = re.compile(r'\x00\x00\x00\x00.\x13\x04\x00')

"""
  We assume that the variable section's length is not larger than 320 bytes,
  it's an arbitrary number. If the job failes to parse correctly, increase it.
"""
MAX_JOB_FILE_SIZE = FIXED_SECTION_LEN + 512 #: increase if .JOB fails to parse


def find_beginning(buf, offset):
    """
    There should be 5 variable length values before the fixed length section,
    see https://msdn.microsoft.com/en-us/library/cc248287.aspx

    Each of them terminates with double null, let's jump 5 x double-nulls back,
    we'll land somewhere in the fixed length section (can't land exactly
    where it ends because there's no unique value separating the two
    sections), read a chunk of memory before and after where we landed and
    find in this chunk a unique value that is always at a given offset in the
    fixed length section.

    The unique value that was used is '0000 0000 ??13 0400', which are Exit
    Code (offset: 40-44) and Status (offset: 44-48). Once identified, we just
    jump back to the beginning of the fix length section and grab enough bytes
    to carve the entire job (the excess bytes are ignored by the parser).

    """
    def go_back_to_nulls(buf, offset):
        buf.seek(offset)
        previous = None
        while True:
            current = buf.read_byte()
            buf.seek(buf.tell() - 1) # return to where we read from
            if current == '\x00' and previous == '\x00':
                return buf.tell()
            buf.seek(buf.tell() - 1) # jump back by 1
            previous = current

    new_offset = offset + 2 # adding 2 because we'll subtract 2 in the loop
    for _ in xrange(5):
        # subtracting 2 to avoid '\x00\x??\x00\x00\x00' being hit on twice
        new_offset = go_back_to_nulls(buf, new_offset - 2)

    # grab a chunk of memory that will be searched for EXIT_CODE_AND_STATUS_REGEX
    if new_offset - FIXED_SECTION_LEN < 0:
        return None
    buf.seek(new_offset - FIXED_SECTION_LEN)

    snippet = buf.read(FIXED_SECTION_LEN + 8)
    match = EXIT_CODE_AND_STATUS_REGEX.search(snippet)
    if not match:
        # failed verification, probably an FP
        return None
    status_code_offset = match.start()

    return (new_offset - FIXED_SECTION_LEN + status_code_offset - EXIT_CODE_OFFSET)

def carve_out(buf, offset):
    """
    Flush the job file.
    """
    buf.seek(offset)
    return buf.read(MAX_JOB_FILE_SIZE)

def main(args):
    if len(args) != 3:
        print('Usage: %s BLOB.BIN OUT_DIR' % os.path.basename(args[0]))
        exit(1)

    in_file, out_dir = args[1:]

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
        print('[*] Created output folder: ' + os.path.abspath(out_dir))

    # The magic string is a unicode comment that's preceded by its size
    # (including the bytes for the size)
    magic_string = ('%c%s' % (len(JOB_COMMENT)+1, JOB_COMMENT)).encode('utf-16-le')

    i = 1
    with open(args[1], 'r+b') as i_file:
        print('[*] Searching...')
        mm = mmap.mmap(i_file.fileno(), 0)
        offset = mm.find(magic_string)
        while offset >= 0:
            job_offset = find_beginning(mm, offset)
            if job_offset:
                print('[+] Found hit: 0x%x' % job_offset)
                data = carve_out(mm, job_offset)
                o_file = file(os.path.join(out_dir, 'carved_%s.job' % i), 'wb')
                o_file.write(data)
                o_file.close()
                i += 1
            else:
                print('[-] Failed verification')
            mm.seek(offset+1)
            offset = mm.find(magic_string)
        print('[*] Done')

if __name__ == '__main__':
    main(sys.argv)

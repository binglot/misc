#-------------------------------------------------------------------------------
# Name:        job_files_carver.py
# Purpose:     To carve out Windows schedule task (.JOB) files from BLOBs of
#              data, such as a memory dump or a page file.
#              The script is relatively slow because it searches for a match on
#              a regular expression that represents the Fixed Length data
#              section. Once it's found, it determines the size of the Variable
#              Length data section, which in turn is very quick.
#
# Author:      Bartosz Inglot
#
# Created:     2015-09-24
# Licence:     GNU General Public License v2.0 (GPL-2.0)
#-------------------------------------------------------------------------------

import sys, os, mmap, re, struct

JOB_MATCHING_REGEX = re.compile(r"""
    # The Regex matches the entire Fixed Section of a JOB file (68 bytes)

    .{4}                            # Should be fixed, but observed random values
    .{16}                           # UUID, random 16 bytes
    .{1}\x00                        # AppNameLenOffset, should be a small number
    .{10}                           # 5 x 2byte unpredictable fields
    .{1}\x00\x00\x00                # Priority, only bytes 23-26 change
    .{4}                            # MaxRunTime, unpredictable
    \x00\x00\x00\x00                # ExitCode, should be always 4 x "00"
    [\x00-\x08]\x13\x04\x00         # Status, values from jobparser.py by Gleeda
    .{4}                            # Flags
    .{3}\x00.{1}\x00.{1}\x00        # RunDate, besides the year and milisecods
    .{1}\x00.{1}\x00.{1}\x00.{2}    #   the 2nd byte are always zeros
    """, re.DOTALL | re.VERBOSE)

RUNDATE_MATCHING_REGEX = re.compile(r"""
  # The Regex matches the last 16 bytes of Fixed Section which is RunDate
  # it was also observed to be filled with only zeros
  (?:
    (?:
    \x00{16}                        # Only zeros
    )
  |
    (?:
    .{1}\x07                        # Year, between 1601 and 30827
    [\x01-\x0c]\x00                 # Month, between 1 and 12
    [\x00-\x06]\x00                 # Weekday, between 0 and 6
    [\x01-\x1f]\x00                 # Day, between 1 and 31
    [\x00-\x17]\x00                 # Hour, between 0 and 23
    [\x00-\x3b]\x00                 # Minute, between 0 and 59
    [\x00-\x3b]\x00                 # Second, between 0 and 59
    .{1}[\x00-\x03]                 # MiliSeconds, between 0 and 999
    )
  $)                                # Ensure it's the last bytes
    """, re.DOTALL | re.VERBOSE)

PRIORITY_MATCHING_REGEX = re.compile(r"""
  # The Regex matches Priority in the Fixed Section, which is limited to 4 values.
  (?:^
    .{32}                           # Skip the bytes before
    [\x08\x10\x20\x40]\x00\x00\x00  # Priority
    .{32}                           # Skip the bytes after
  )$
    """, re.DOTALL | re.VERBOSE)

def pass_verification(data):
    """
    For performance reasons, the JOB matching regular expression is not as strict
    as it could be. This method attempts to validate the remaining fields to
    reduce the amount of false positives.
    """
    if not RUNDATE_MATCHING_REGEX.search(data):
        return False
    if not PRIORITY_MATCHING_REGEX.search(data):
        return False
    # Theoretically the Flags field should be predictable too but some completely
    # random values were observed and therefore the regex is not implemented.
##    if not FLAGS_MATCHING_REGEX.search(data):
##        return False
    # Finally, the maximum job file size is unknown but let's set a limit to
    # avoid accidental export of large files.
    if len(data) > 0x2000:
        return False
    return True

def is_valid_unicode_str(buf, start_offset, end_offset):
    """
    Verify a set of bytes could be a valid Unicode string.
    It's done by assuming the following criteria:
        1) It's even length.
        2) It ends with two NULL bytes
        3) It's split into two-byte pairs: 1st is never NULL, 2nd is always NULL
    """
    str_len = end_offset - start_offset - 2
    if str_len > 0:
        # Can't be odd length!
        if str_len % 2 == 1:
            return False
        # Check the bytes
        buf.seek(start_offset)
        text = buf.read(str_len)
        buf.seek(end_offset)
        for i in xrange(str_len / 2):
            pair_byte_1 = text[i*2]
            pair_byte_2 = text[i*2 + 1]
            if pair_byte_1 == '\x00' or pair_byte_2 != '\x00':
                return False
    return True


def var_size_section_len(buf, start_offset):
    """
    Find the size of the variable-length data section. It's done by ignoring the
    first 2 bytes (Running Instance Count) and then jumping over 5 fields by
    locating two nulls that end specially formatted Unicode strings. The fields
    are Application Name, Parameters, Working Directory, Author, Comment.
    Then we jump the User Data and Reserved Data fields by reading their size.
    The following field are triggers, we jump over by reading the countr number
    and multiplying by the fixed length of each trigger (48 bytes). Finally,
    we check if the optional Job Signature Header is available and if so we jump
    over the Job Signature; otherwise we return we the triggers end.
    """
    def find_double_nulls(buf, start_offset):
        buf.seek(start_offset)
        while True:
            pair_byte_1 = buf.read_byte()
            pair_byte_2 = buf.read_byte()
            if pair_byte_1 == '\x00' and pair_byte_2 == '\x00':
                return buf.tell()

    # jump the Running Instance Count field
    buf.seek(start_offset + 2)
    # jump 5 fields that end with two null bytes
    end_offset = start_offset
    for _ in xrange(5):
        str_offset = end_offset
        end_offset = find_double_nulls(buf, end_offset)
        # Fail if the strings aren't Unicode
        if not is_valid_unicode_str(buf, str_offset, end_offset):
            return -1
    # jump User Data
    user_data_len = struct.unpack('<H', buf.read(2))[0]
    end_offset += 2 + user_data_len
    buf.seek(end_offset)
    # jump Reserved Data
    reserved_data_len = struct.unpack('<B', buf.read(2)[0])[0]# skip TASKRESERVED1
    end_offset += 2 + reserved_data_len
    buf.seek(end_offset)
    # jump Triggers (48 bytes each)
    triggers_count = struct.unpack('<H', buf.read(2))[0]
    end_offset += 2 + triggers_count*48
    buf.seek(end_offset)
    # jump Job Signature (*optional*)
    job_signature_header = buf.read(4)
    if job_signature_header == '\x01\x00\x01\x00':
        end_offset += 12

    # reset to the beginning of the variable-length section
    buf.seek(start_offset)
    # voila!
    return end_offset - start_offset

def get_var_len_section(buf, offset):
    """
    Get the section length, validate it and then carve it.
    """
    try:
        variable_len_size = var_size_section_len(buf, offset)
        if variable_len_size > 0:
            data = buf.read(variable_len_size)
            # Extra verification step: it can't be just null bytes
            return data if data != ''.join(('\00',)*16) else None
    except:
        pass
    return None

def carve_job_file(buf, offset):
    """
    Search and return data that appear to be a JOB file. It's done by matching
    the fixed-length data section  with a Regular Expression and then trying to
    determine the size of the variable-length data section.
    """
    match = JOB_MATCHING_REGEX.search(buf, offset)
    if not match:
        return (None,)*3
    offset = match.start()
    print('[+] Found hit: 0x%x' % offset)
    # piece together the 2 data sections
    fixed_len_data = match.group() if pass_verification(match.group()) else None
    variable_len_data = get_var_len_section(buf, match.end())
    # return: data, where it was found, and if the data passed verification test
    return fixed_len_data, variable_len_data, offset

def main(args):
    if len(args) != 3:
        print('Usage: %s BLOB.BIN OUT_DIR' % os.path.basename(args[0]))
        exit(1)

    in_file, out_dir = args[1:]

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
        print('[*] Created output folder: ' + os.path.abspath(out_dir))

    offset, i = (-1, 1) # initiating loop values
    with open(args[1], 'r+b') as i_file:
        print('[*] Searching...')
        mm = mmap.mmap(i_file.fileno(), 0)
        while True:
            result = carve_job_file(mm, offset+1) # +1 to avoid infinite loop
            fixed_len_data, variable_len_data, offset = result
            if offset != None:
                if None in result:
                    print('[-] Failed verification')
                    continue
                # Writing the job file
                o_filename = os.path.join(out_dir, 'carved_%s.job' % i)
                o_file = file(o_filename, 'wb')
                o_file.write(fixed_len_data + variable_len_data)
                o_file.close()
                print(' Written: ' + o_filename)
                i += 1
            else:
                break
        print('[*] Done')

if __name__ == '__main__':
    main(sys.argv)

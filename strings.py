import sys, re, os

n = 6
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

regexp = rb"([%s]{%d,})|((?:[%s]\x00){%d,}[%s])" % (ASCII_BYTE, n, ASCII_BYTE, (n-1), ASCII_BYTE)
ascii_only_regexp = rb"([%s]{%d,})" % (ASCII_BYTE, n)

pattern = re.compile(regexp)

def process(stream):
    data = stream.read()
    for match in pattern.finditer(data):
        yield match.group()

def main(args):
    if len(args) != 2:
        print('Usage: %s <input_file>'  % os.path.basename(args[0]))
        sys.exit(1)
    with open(args[1], 'rb') as i_file:
        for s in process(i_file):
            decoded = ''
            if re.match(ascii_only_regexp, s):
                decoded = '[A] ' + s.decode('ascii') 
            else: 
                decoded = '[W] ' + (s+b'\00').decode('utf-16-le')
            print(decoded)

if __name__ == "__main__":
    main(sys.argv)

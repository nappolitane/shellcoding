import argparse

def read_raw(fname):
    f = open(fname, "rb")
    ba = bytes(f.read())
    by_list = []
    for b in ba:
        by_list.append(str(hex(b)))
    return by_list

def write_cstyle(by_list):
    shellcode_length = len(by_list)
    print("unsigned char shellcode[] = {")
    i = 1
    for b in by_list:
        if i == (shellcode_length):
            print(b)
        elif i % 12 == 0:
            print(b + ",")
        else:
            print(b + ", ", end='')
        i += 1
    print("};")
    print("unsigned int shellcode_len = {};".format(shellcode_length))

if __name__ =="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputfile', help='Input shellcode raw file', required=True)
    args = parser.parse_args()

    byte_list = read_raw(args.inputfile)
    write_cstyle(byte_list)

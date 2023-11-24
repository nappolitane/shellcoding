import argparse
from subprocess import check_output

def parse_disassembly(objdump_outp):
    by_list = []
    lines = objdump_outp.split('\n')
    for l in lines:
        if len(l.split(':')) > 1 and "file" not in l:
            for hl in l.split(':')[1:]:
                if len(hl.split('\t')) > 1:
                    by = hl.split('\t')[1].strip().split(' ')
                    for b in by:
                        by_list.append(b)
    return by_list

def write_cstyle(by_list):
    shellcode_length = len(by_list)
    print("unsigned char shellcode[] = {")
    i = 1
    for b in by_list:
        if i == (shellcode_length):
            print("0x" + b)
        elif i % 12 == 0:
            print("0x" + b + ",")
        else:
            print("0x" + b + ", ", end='')
        i += 1
    print("};")
    print("unsigned int shellcode_len = {};".format(shellcode_length))

def write_raw(by_list):
    by_arr = []
    for b in by_list:
        by_arr.append(int(b,16))
    newfile = open("shellcode_raw.bin","wb")
    newfile.write(bytes(by_arr))
    return

if __name__ =="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputfile', help='Input object file', required=True)
    parser.add_argument('-o', '--outtype', help='Output type: cstyle | raw', required=True)
    args = parser.parse_args()

    disassmbly_outp = check_output("objdump -M intel -D " + args.inputfile, shell=True)
    bytes_list = parse_disassembly(disassmbly_outp.decode("utf-8"))

    if args.outtype == "cstyle":
        write_cstyle(bytes_list)
    elif args.outtype == "raw":
        write_raw(bytes_list)
    else:
        print("Error: Wrong output type argument. Please choose between: cstyle | raw")

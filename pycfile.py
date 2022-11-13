import sys, struct, marshal, binascii, time, dis, platform

# https://stackoverflow.com/a/42720524
def parse_pyc(file):
    magic = file.read(4)
    bit_field = None
    timestamp = None
    hashstr = None
    size = None

    if sys.version_info.major == 3 and sys.version_info.minor >= 7:
        bit_field = int.from_bytes(file.read(4), byteorder=sys.byteorder)
        if bit_field & 1 == 1:
            hashstr = file.read(8)
        else:
            timestamp = file.read(4)
            size = file.read(4)
            size = struct.unpack('I', size)[0]
    elif sys.version_info.major == 3 and sys.version_info.minor >= 3:
        timestamp = file.read(4)
        size = file.read(4)
        size = struct.unpack('I', size)[0]
    else:
        timestamp = file.read(4)

    code = marshal.load(file)

    magic = binascii.hexlify(magic).decode('utf-8')
    if timestamp != None:
        timestamp = time.asctime(time.localtime(struct.unpack('I', timestamp)[0]))

    return code

def get_pyarmor_bytes(file):
    code = parse_pyc(file)

    for inst in dis.get_instructions(code):
        if inst.opname == "LOAD_CONST":
            if isinstance(inst.argval, bytes):
                possible_pyarmor = inst.argval[:7]
                if possible_pyarmor == b"PYARMOR":
                    return inst.argval
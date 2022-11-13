from decoder import Decoder
from enums import *
import sys

def main():
    if len(sys.argv) < 3:
        print("bone_density")
        print("usage:")
        print("  python bd.py encrypted_file.pyc _pytransform.dll")
        print("  python bd.py encrypted_file.pyc pytransform.pyd")
        print("    use the pytransform.pyc file if you have it,")
        print("    otherwise, use the _pytransform.dll version.")
        print("")
        print("note: only windows dlls/pycs are supported right now.")
        exit(1)
    
    pyc_path = sys.argv[1]
    asm_path = sys.argv[2]

    decode_mode = DecodeMode.Unknown
    if asm_path.lower().endswith("_pytransform.dll"):
        decode_mode = DecodeMode.BasicMode
    elif asm_path.lower().endswith("pytransform.pyd"):
        decode_mode = DecodeMode.SuperMode
    else:
        print("I can't figure out what mode to decode in")
        print("since the assembly file name isn't either")
        print("_pytransform.dll or pytransform.pyd.")
        print("Please rename it back to the original name.")
        print("If it came like this, it's probably not supported.")
        exit(1)
    
    decoder = Decoder(pyc_path, asm_path, decode_mode)
    decoder.decode()

if __name__ == "__main__":
    main()
from decrypt import decrypt_buffer, decrypt_buffer_block, decrypt_buffer_inline
from unscramble import correct_py_bytecode, unscramble_opcode_mixer
from util import read_mem_u32, write_mem_u32, get_zoombie
from pyarmorvm_code import decode_key_and_iv
from pycfile import get_pyarmor_bytes
from code_fix import CodeFixer, CodeFixerSuper
from Crypto.Cipher import AES
from enums import DecodeMode
import importlib
import marshal
import base64
import sys
import os

class Decoder():
    def __init__(self, pyc_path:str, asm_path:str, mode:DecodeMode):
        self.pyc_path = pyc_path
        self.asm_path = asm_path
        self.mode = mode
    
    def decode(self):
        self.load_files()
        pyshield_lic_key, pyshield_lic_iv = self.decode_pyshield_lic(self.pyshield_lic_enc)
        product_key_key, product_key_iv = self.decode_product_key(self.product_key_enc, pyshield_lic_key, pyshield_lic_iv)
        license_info = self.decode_license_lic(self.license_lic_enc)

        print("pyarmor license info:")
        for item in license_info:
            print(f"  {item}")
        
        pyarmor_bytes_enc = self.get_pyarmor_bytes()
        pyarmor_bytes_key, pyarmor_bytes_nonce = self.get_pyarmor_key_nonce(product_key_key, pyarmor_bytes_enc)
        pyarmor_bytes = self.decode_pyarmor_bytes(pyarmor_bytes_enc, pyarmor_bytes_key, pyarmor_bytes_nonce)

        if self.mode == DecodeMode.SuperMode:
            zoombie = get_zoombie(product_key_key, product_key_iv)
            code_fixer = CodeFixerSuper(product_key_key, product_key_iv, zoombie)
            
            pyarmor_marshal = marshal.loads(pyarmor_bytes)
            pyarmor_marshal_fix = code_fixer.deobfusc_codeobj_first(pyarmor_marshal)

            armor_wrap_pyc = importlib._bootstrap_external._code_to_timestamp_pyc(pyarmor_marshal_fix) # type: ignore
            
            fix_pyc_filename = sys.argv[1] + ".fix.pyc"
            self.write_pyc(armor_wrap_pyc, fix_pyc_filename)
            self.decompile_pyc(fix_pyc_filename)
        else: # normal mode
            code_fixer = CodeFixer(product_key_key, product_key_iv)

            pyarmor_marshal = marshal.loads(pyarmor_bytes)
            pyarmor_marshal_fix = code_fixer.deobfusc_codeobj(pyarmor_marshal)

            armor_wrap_pyc = importlib._bootstrap_external._code_to_timestamp_pyc(pyarmor_marshal_fix) # type: ignore
            
            fix_pyc_filename = sys.argv[1] + ".fix.pyc"
            self.write_pyc(armor_wrap_pyc, fix_pyc_filename)
            self.decompile_pyc(fix_pyc_filename)
    
    def load_files(self):
        # last four bytes may be an unsafe check
        # remove them if you can't find this whole string
        match = b"\x60\x70\x00\x0f\x00\x10\x00\x00"
        
        with open(self.asm_path, "rb") as f:
            data = f.read()
        
        data_pos = -1

        p = 0
        while p < len(data):
            if data[p:p+8] == match[0:8]:
                data_pos = p + 8
                break
            
            p += 4
        
        if data_pos == -1:
            print("oof, looks like we couldn't find the decryption files")
            print("look at load_files of decoder and fix the match string")
            exit(1)

        pyshield_lic_ptr = read_mem_u32(data, data_pos + 0x00) + data_pos + 24
        pyshield_lic_len = read_mem_u32(data, data_pos + 0x04)
        product_key_ptr  = read_mem_u32(data, data_pos + 0x08) + data_pos + 24
        product_key_len  = read_mem_u32(data, data_pos + 0x0c)
        license_lic_ptr  = read_mem_u32(data, data_pos + 0x10) + data_pos + 24
        license_lic_len  = read_mem_u32(data, data_pos + 0x14)

        self.pyshield_lic_enc = data[pyshield_lic_ptr : pyshield_lic_ptr+pyshield_lic_len]
        self.product_key_enc = data[product_key_ptr : product_key_ptr+product_key_len]
        self.license_lic_enc = data[license_lic_ptr : license_lic_ptr+license_lic_len]

    def decode_pyshield_lic(self, pyshield_lic):
        pyshield_lic = decrypt_buffer_inline(pyshield_lic)
        return decode_key_and_iv(pyshield_lic)
    
    def decode_product_key(self, product_key, pyshield_lic_key, pyshield_lic_iv):
        product_key = decrypt_buffer(product_key, pyshield_lic_key, pyshield_lic_iv)
        return decode_key_and_iv(product_key)
    
    def decode_license_lic(self, license_lic):
        license_lic = base64.b64decode(license_lic)
        header_len = license_lic[0] # no idea what happens if this is too long
        return license_lic[1:header_len+1].decode("utf-8").split("\n")
    
    def get_pyarmor_bytes(self):
        with open(self.pyc_path, "rb") as f:
            pyarmor_bytes = get_pyarmor_bytes(f)
        
        return pyarmor_bytes
    
    def get_pyarmor_key_nonce(self, product_key, pyarmor_bytes):
        key = [0]*16

        key_a1 = read_mem_u32(product_key, 0x26)
        key_a2 = read_mem_u32(pyarmor_bytes, 0x28)
        write_mem_u32(key, 0x00, key_a1 ^ key_a2)

        key_b1 = read_mem_u32(product_key, 0x2a)
        key_b2 = read_mem_u32(pyarmor_bytes, 0x2c) - 0x3b22
        write_mem_u32(key, 0x04, key_b1 ^ key_b2)

        key_c1 = read_mem_u32(product_key, 0x2e)
        key_c2 = read_mem_u32(pyarmor_bytes, 0x30) + 0x802f
        write_mem_u32(key, 0x08, key_c1 ^ key_c2)

        key_d1 = read_mem_u32(product_key, 0x32)
        key_d2 = read_mem_u32(pyarmor_bytes, 0x34) + 0x251a
        write_mem_u32(key, 0x0c, key_d1 ^ key_d2)

        key = bytes(key)
        nonce = bytes(pyarmor_bytes[0x28:0x34])

        return (key, nonce)
    
    def decode_pyarmor_bytes(self, pyarmor_bytes, key, nonce):
        data_size = read_mem_u32(pyarmor_bytes, 0x20)
        data_start = read_mem_u32(pyarmor_bytes, 0x1c)
        data = pyarmor_bytes[data_start : data_start+data_size]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt(data)
    
    def write_pyc(self, bytes, path):
        with open(path, "wb") as f:
            f.write(bytes)
    
    def decompile_pyc(self, path):
        try:
            if os.name == "nt":
                os.system("pycdc " + path)
            else:
                os.system("./pycdc " + path)
        except:
            print("oof, decompile error")
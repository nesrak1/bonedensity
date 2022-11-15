import sys

from decrypt import decrypt_buffer_basic_xor, decrypt_buffer_block, decrypt_ctr, decrypt_des
from unscramble import correct_py_bytecode, unscramble_opcode_mixer

# from unpyarmor code: https://github.com/nlscc/unpyarmor
# note: there are still a lot of issues with the
# resulting trimmed code in some modes. need to
# figure out which modes are working and which aren't.

class CodeFixer():
    # JUMP_IF_FALSE_OR_POP, JUMP_IF_TRUE_OR_POP, JUMP_ABSOLUTE, POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE, CONTINUE_LOOP, JUMP_IF_NOT_EXC_MATCH
    #             0x6f   70   71   72   73   77   79
    JUMP_OPCODES = [111, 112, 113, 114, 115, 119, 121]

    def __init__(self, key, iv):
        if sys.hexversion >= 0x3080000: # 3.8
            self.JUMP_OPCODES.remove(119) # CONTINUE_LOOP
        
        self.key = key
        self.iv = iv

    def fix_code(self, code, stub_size, end_code):
        #nop_count = stub_size // 2
        #code = b"\x09\x00"*nop_count + code + end_code

        # replace jump to stub with return
        code = code[:-2] + b"S\x00" # RETURN_VALUE
        # fix absolute jumps
        extend = None
        code = bytearray(code)
        for i in range(0, len(code), 2):
            op = code[i]
            arg = code[i+1]
            if op == 144: # extend opcode
                extend = arg << 8
                continue
            if op in self.JUMP_OPCODES:
                if extend is not None:
                    arg |= extend
                    arg -= stub_size
                    if arg < 0:
                        # convert to return, we're trying to jump back into the stub
                        code[i] = 0x53
                        code[i+1] = 0x00
                    else:                
                        code[i+1] = arg & 0xff
                        code[i-1] = arg >> 8
                else:
                    arg -= stub_size
                    if arg < 0:
                        # convert to return, we're trying to jump back into the stub
                        code[i] = 0x53
                        code[i+1] = 0x00
                    else:
                        code[i+1] = arg
            extend = None

        return bytes(code)

    def decrypt_code_enter_exit(self, code, flags):
        # remove stub (different versions have different size stubs,
        # these are actually hardcoded into pyarmor)
        if sys.hexversion < 0x3080000: # 3.7
            sbeg, send = 16, 16
        elif sys.hexversion >= 0x3080000: # 3.8
            sbeg, send = 32, 16
        else:
            raise Exception(f"invalid python version?: {sys.hexversion}")
        
        og_code = code
        enc = code[sbeg:-send]

        if flags & 0x8000000:
            if flags & 0x2000000:
                print("decoding mode 1...")
                code = decrypt_buffer_block(enc[:-16], self.key[0x32:0x4a], code[-16:], True)
                code = self.fix_code(code, 16, og_code[-send-16:-16])
            else:
                print("decoding mode 2...")
                code = decrypt_buffer_basic_xor(enc, self.key[0x32:0x4a])
                code = self.fix_code(code, sbeg, og_code[-send:])
        else:
            if flags & 0x2000000:
                print("decoding mode 3...")
                code = decrypt_buffer_block(enc[:-16], self.key[0x32:0x4a], code[-16:], False)
                code = self.fix_code(code, 16, og_code[-send-16:-16])
            else:
                print("decoding mode 4...")
                code = decrypt_des(enc, self.key[0x32:0x4a], self.iv, False)
                code = self.fix_code(code, sbeg, og_code[-send:])

        return code

    def decrypt_code_armor_wrap(self, code, flags):
        # Calculate the start offset
        code_start = 0
        #for i in range(0, len(code), 2):
        #    if code[i] == 110: # JUMP_FORWARD
        #        code_start = i+2
        #        break
        code_start += 0x10
        
        extra_ending = 0
        if flags & 0x2000000:
            extra_ending = 16

        enc = code[code_start:-8-extra_ending] # Remove stub
        print(" ".join([hex(x)[2:].zfill(2) for x in code]))

        if flags & 0x40000000: # obf_code == 1
            print("decoding mode 5...")
            code = bytes(decrypt_buffer_basic_xor(enc, self.key[0x32:0x4a]))
        elif flags & 0x8000000: # obf_code == 2
            print("decoding mode 6...")
            code = bytes(decrypt_des(enc, self.key[0x00:0x18], self.iv, False))
        
        return code

    def decrypt_code_armor(self, code, flags):
        # Calculate the start offset
        code_start = 0
        for i in range(0, len(code), 2):
            if code[i] == 110: # JUMP_FORWARD
                code_start = i+2
                break
        
        extra_ending = 0
        if flags & 0x2000000:
            extra_ending = 16

        enc = code[code_start:-8-extra_ending] # Remove stub

        if flags & 0x8000000:
            if flags & 0x2000000:
                print("decoding mode 7...")
                code = decrypt_ctr(enc[:-16], self.key[0x19:0x29], code[-16:])
            else:
                print("decoding mode 8...")
                code = decrypt_buffer_basic_xor(enc, self.key[0x32:0x4a])
        else:
            if flags & 0x2000000:
                print("decoding mode 9...")
                code = decrypt_buffer_block(enc[:-16], self.key[0x32:0x4a], code[-16:], False)
            else:
                print("decoding mode 10...")
                code = decrypt_des(enc, self.key[0x19:0x31], self.iv, False)
        
        return code

    def deobfusc_codeobj(self, co):
        # Deobfuscate a code object
        code = co.co_code
        flags = co.co_flags
        consts = []
        # decode sub-functions
        for i in range(len(co.co_consts)):
            const = co.co_consts[i]
            if isinstance(const, type(co)):
                if i+1 < len(co.co_consts):
                    # not reliable
                    print(f"fixing {co.co_consts[i+1]}...")
                else:
                    print("fixing <unknown>...")
                
                const = self.deobfusc_codeobj(const)
            
            consts.append(const)
        
        print(f"flags: {flags:08x}")
        if flags & 0x48000000:
            if "__armor_enter__" in co.co_names and "__armor_exit__" in co.co_names: # wrap_mode == 1
                code = self.decrypt_code_enter_exit(co.co_code, flags)
            elif "__armor__" in co.co_names: # wrap_mode == 0
                code = self.decrypt_code_armor(co.co_code, flags)
            elif "__armor_wrap__" in co.co_names: # wrap_mode == 0
                code = self.decrypt_code_armor_wrap(co.co_code, flags)
            else:
                print("warning: could not detect stub in", co)
        
        # remove obfuscation flags
        # note: 0x20000000 means allow external usage
        flags &= ~(0x40000000 | 0x20000000 | 0x8000000)
        # change the code and flags of the code object to the deobfuscated version
        if sys.hexversion < 0x3080000:
            code_c = type(co)
            co = code_c(co.co_argcount, co.co_kwonlyargcount, co.co_nlocals,
                co.co_stacksize, flags, code, tuple(consts), co.co_names,
                co.co_varnames, co.co_filename, co.co_name, co.co_firstlineno,
                co.co_lnotab, co.co_freevars, co.co_cellvars)
        else:
            # 3.8 changed some code object fields and added 'replace'
            co = co.replace(co_code=code, co_flags=flags, co_consts=tuple(consts))
        
        return co


class CodeFixerSuper():
    # JUMP_IF_FALSE_OR_POP, JUMP_IF_TRUE_OR_POP, JUMP_ABSOLUTE, POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE, CONTINUE_LOOP, JUMP_IF_NOT_EXC_MATCH
    #             0x6f   70   71   72   73   77   79
    JUMP_OPCODES = [111, 112, 113, 114, 115, 119, 121]

    def __init__(self, key, iv, zoombie):
        if sys.hexversion >= 0x3080000: # 3.8
            self.JUMP_OPCODES.remove(119) # CONTINUE_LOOP
        
        self.key = key
        self.iv = iv
        self.zoombie = zoombie
        self.new_mixer = unscramble_opcode_mixer(zoombie)

    def fix_code(self, code, stub_size, end_code):
        #nop_count = stub_size // 2
        #code = b"\x09\x00"*nop_count + code + end_code

        # replace jump to stub with return
        code = code[:-2] + b"S\x00" # RETURN_VALUE
        # fix absolute jumps
        extend = None
        code = bytearray(code)
        for i in range(0, len(code), 2):
            op = code[i]
            arg = code[i+1]
            if op == 144: # extend opcode
                extend = arg << 8
                continue
            if op in self.JUMP_OPCODES:
                if extend is not None:
                    arg |= extend
                    arg -= stub_size
                    if arg < 0:
                        # convert to return, we're trying to jump back into the stub
                        code[i] = 0x53
                        code[i+1] = 0x00
                    else:                
                        code[i+1] = arg & 0xff
                        code[i-1] = arg >> 8
                else:
                    arg -= stub_size
                    if arg < 0:
                        # convert to return, we're trying to jump back into the stub
                        code[i] = 0x53
                        code[i+1] = 0x00
                    else:
                        code[i+1] = arg
            extend = None

        return bytes(code)

    def decrypt_code_armor_wrap(self, code, flags):
        armor_wrap_co_code = code[16:]
        armor_wrap_key = code[-16:]
        
        if flags & 0x8000000:
            if flags & 0x2000000:
                print("decoding mode 1...")
                code = decrypt_ctr(armor_wrap_co_code[:-16], self.key[0x19:0x29], armor_wrap_key)
            else:
                print("decoding mode 2...")
                code = decrypt_buffer_basic_xor(armor_wrap_co_code, self.key[0x32:0x4a])
        else:
            if flags & 0x2000000:
                print("decoding mode 3...")
                code = decrypt_buffer_block(armor_wrap_co_code[:-16], self.key[0x32:0x4a], armor_wrap_key, False)
            else:
                print("decoding mode 4...")
                code = decrypt_des(armor_wrap_co_code, self.key[0x19:0x31], self.iv, False)
        
        correct_py_bytecode(self.new_mixer, code)
        return bytes(code)

    def deobfusc_codeobj_first(self, pyarmor_marshal):
        print(pyarmor_marshal)
        armor_wrap_code = pyarmor_marshal[0]
        armor_wrap_co_code = armor_wrap_code.co_code[16:-16]
        armor_wrap_key = armor_wrap_code.co_code[-16:]
        armor_wrap_flags = armor_wrap_code.co_flags
        armor_wrap_co_consts = pyarmor_marshal[1:]
        return self.deobfusc_codeobj(armor_wrap_code, armor_wrap_co_consts)
    
    def deobfusc_codeobj(self, co, co_consts):
        # Deobfuscate a code object
        code = co.co_code
        flags = co.co_flags
        co_consts_idx = co.co_consts[0]-2
        real_co_consts = co_consts[co_consts_idx]
        consts = []
        # decode sub-functions
        code_idx = 0 # jank af
        for i in range(len(real_co_consts)):
            const = real_co_consts[i]
            if isinstance(const, type(co)):
                if i+1 < len(co_consts):
                    # not reliable
                    print(f"fixing {co_consts[i+1]}...")
                else:
                    print("fixing <unknown>...")
                
                const = self.deobfusc_codeobj(const, co_consts)
                code_idx += 1
            
            consts.append(const)
        
        print(f"flags: {flags:08x}")
        if flags & 0x48000000:
            if "__armor_wrap__" in co.co_names:
                code = self.decrypt_code_armor_wrap(co.co_code, flags)
            else:
                print("warning: could not detect stub in", co)
        
        # remove obfuscation flags
        # note: 0x20000000 means allow external usage
        flags &= ~(0x40000000 | 0x20000000 | 0x8000000)
        # change the code and flags of the code object to the deobfuscated version
        if sys.hexversion < 0x3080000:
            code_c = type(co)
            co = code_c(co.co_argcount, co.co_kwonlyargcount, co.co_nlocals,
                co.co_stacksize, flags, code, tuple(consts), co.co_names,
                co.co_varnames, co.co_filename, co.co_name, co.co_firstlineno,
                co.co_lnotab, co.co_freevars, co.co_cellvars)
        else:
            # 3.8 changed some code object fields and added 'replace'
            co = co.replace(co_code=code, co_flags=flags, co_consts=tuple(consts))
        
        return co
from enum import Enum
import io

class Opcode(Enum):
    # not directly gnu lightning instructions
    s_init = 0x01 # s_init <local_count> # init vm. local_count includes the 3 required arguments
    s_execute = 0x02
    s_ld_ptr = 0x03 # s_ld_ptr <dst> <ptr> # load ptr from a list (see ptr_list) and store into dst
    s_stxi_local = 0x04 # s_stxi_local <local_idx> <src> # store from register src to local_idx
    s_ldxi_local = 0x05 # s_ldxi_local <local_idx> <dst> # load argument from local_idx to register dst
    s_call_sysfun = 0x0e # s_call_sysfun <fun_idx> # call system function from a list (see fun_list)
    s_finishi_sysfun = 0x0f # s_finishi_sysfun <fun_idx>
    # gnu lightning instructions
    prepare = 0x10 # prepare next finish call
    pushargi = 0x11 # pushargi {imm} # push imm
    pushargr = 0x12 # pushargr <reg> # push reg
    reti = 0x14 # reti <imm> # reti
    retr = 0x15 # retr <reg> # retr
    retval_l = 0x16 # retval_l <reg> # store return value from call into reg
    movr = 0x20 # movr <dst> <src> # move src value into dst
    movi = 0x21 # movi <dst> {imm} # move imm into dst
    ldr_l = 0x30 # ldr_l <dst> <addr> # load value at address register addr into register dst
    ldr_ui = 0x31 # ldr_ui <dst> <addr> # load value at address register addr into register dst
    ldxr_uc = 0x32 # ldxr_uc <dst> <addr_off> # load value at (address register+off register) addr into register dst
    str_l = 0x40 # str_l <addr> <src> # store value of src into address register addr
    str_i = 0x41 # str_i <addr> <src> # store value of src into address register addr
    stxr_c = 0x42 # stxr_c <addr> <src_off> # store value of src into (address register+off register) addr
    addr = 0x100 # addr <dst> <reg> # dst += reg
    addi = 0x101 # addi <dst> {imm} # dst += imm
    subr = 0x110 # subr <dst> <reg> # dst -= reg
    subi = 0x111 # subi <dst> {imm} # dst -= imm
    mulr = 0x120 # mulr <dst> <reg> # dst *= reg
    muli = 0x121 # muli <dst> {imm} # dst *= imm
    divr = 0x130 # divr <dst> <reg> # dst /= reg
    divi = 0x131 # divi <dst> {imm} # dst /= imm
    remr = 0x140 # remr <dst> <reg> # dst %= reg
    remi = 0x141 # remi <dst> {imm} # dst %= imm
    xorr = 0x150 # xorr <dst> <reg> # dst ^= reg
    xori = 0x151 # xori <dst> {imm} # dst ^= imm
    lshr = 0x160 # lshr <dst> <reg> # dst <<= reg
    lshi = 0x161 # lshi <dst> {imm} # dst <<= imm
    label = 0x200 # label <label_idx> # store label at index
    forward = 0x201 # forward <label_idx> # store forward label at index
    link = 0x203 # link <label_idx> # store link label at index
    patch = 0x204 # patch <label_idx> # apply patch
    patch_at = 0x205 # patch_at <cond> <label_idx> # apply patch 
    bltr = 0x300 # bltr <label_idx> <xy_registers> # branch if less than (reg[b & 0xf] < reg[b >> 4])
    blti = 0x301 # blti <label_idx> <x_register> {y_value} # branch if less than (reg[b] < i)
    bgtr = 0x310 # bgtr <label_idx> <xy_registers> # branch if greater than (reg[b & 0xf] > reg[b >> 4])
    bgti = 0x311 # bgti <label_idx> <x_register> {y_value} # branch if greater than (reg[b] > i)
    beqr = 0x320 # beqr <label_idx> <xy_registers> # branch if equal to (reg[b & 0xf] == reg[b >> 4])
    beqi = 0x321 # beqi <label_idx> <x_register> {y_value} # branch if equal to, sign ignored (abs(reg[b]) == abs(i))

size_map = {
    Opcode.s_init: 1,
    Opcode.s_execute: 2,
    Opcode.s_mov_func_inf: 1,
    Opcode.s_stxi_local: 1,
    Opcode.s_ldxi_local: 1,
    Opcode.s_call_sysfun: 1,
    Opcode.s_finishi_sysfun: 1,
    Opcode.prepare: 1,
    Opcode.pushargi: 1,
    Opcode.pushargr: 1,
    Opcode.reti: 1,
    Opcode.retr: 1,
    Opcode.retval_l: 1,
    Opcode.movr: 1,
    Opcode.movi: 2,
    Opcode.ldr_l: 1,
    Opcode.ldr_ui: 1,
    Opcode.ldxr_uc: 1,
    Opcode.str_l: 1,
    Opcode.str_i: 1,
    Opcode.stxr_c: 1,
    Opcode.addr: 1,
    Opcode.addi: 2,
    Opcode.subr: 1,
    Opcode.subi: 2,
    Opcode.mulr: 1,
    Opcode.muli: 2,
    Opcode.divr: 1,
    Opcode.divi: 2,
    Opcode.remr: 1,
    Opcode.remi: 2,
    Opcode.xorr: 1,
    Opcode.xori: 2,
    Opcode.lshr: 1,
    Opcode.lshi: 2,
    Opcode.label: 1,
    Opcode.forward: 1,
    Opcode.link: 1,
    Opcode.patch: 1,
    Opcode.patch_at: 1,
    Opcode.bltr: 1,
    Opcode.blti: 2,
    Opcode.bgtr: 1,
    Opcode.bgti: 2,
    Opcode.beqr: 1,
    Opcode.beqi: 2
}

register_operand_count_map = {
    Opcode.s_init: 1,
    Opcode.s_execute: 1,
    Opcode.s_mov_func_inf: 2,
    Opcode.s_stxi_local: 2,
    Opcode.s_ldxi_local: 2,
    Opcode.s_call_sysfun: 1,
    Opcode.s_finishi_sysfun: 1,
    Opcode.prepare: 0,
    Opcode.pushargi: 0,
    Opcode.pushargr: 1,
    Opcode.reti: 1,
    Opcode.retr: 1,
    Opcode.retval_l: 1,
    Opcode.movr: 2,
    Opcode.movi: 1,
    Opcode.ldr_l: 2,
    Opcode.ldr_ui: 2,
    Opcode.ldxr_uc: 3,
    Opcode.str_l: 2,
    Opcode.str_i: 2,
    Opcode.stxr_c: 3,
    Opcode.addr: 2,
    Opcode.addi: 1,
    Opcode.subr: 2,
    Opcode.subi: 1,
    Opcode.mulr: 2,
    Opcode.muli: 1,
    Opcode.divr: 2,
    Opcode.divi: 1,
    Opcode.remr: 2,
    Opcode.remi: 1,
    Opcode.xorr: 2,
    Opcode.xori: 1,
    Opcode.lshr: 2,
    Opcode.lshi: 1,
    Opcode.label: 1,
    Opcode.forward: 1,
    Opcode.link: 1,
    Opcode.patch: 1,
    Opcode.patch_at: 2,
    Opcode.bltr: 3,
    Opcode.blti: 3,
    Opcode.bgtr: 3,
    Opcode.bgti: 3,
    Opcode.beqr: 3,
    Opcode.beqi: 3
}

uses_imm_map = {
    Opcode.s_init: False,
    Opcode.s_execute: False,
    Opcode.s_mov_func_inf: False,
    Opcode.s_stxi_local: False,
    Opcode.s_ldxi_local: False,
    Opcode.s_call_sysfun: False,
    Opcode.s_finishi_sysfun: False,
    Opcode.prepare: False,
    Opcode.pushargi: True,
    Opcode.pushargr: False,
    Opcode.reti: False,
    Opcode.retr: False,
    Opcode.retval_l: False,
    Opcode.movr: False,
    Opcode.movi: True,
    Opcode.ldr_l: False,
    Opcode.ldr_ui: False,
    Opcode.ldxr_uc: False,
    Opcode.str_l: False,
    Opcode.str_i: False,
    Opcode.stxr_c: False,
    Opcode.addr: False,
    Opcode.addi: True,
    Opcode.subr: False,
    Opcode.subi: True,
    Opcode.mulr: False,
    Opcode.muli: True,
    Opcode.divr: False,
    Opcode.divi: True,
    Opcode.remr: False,
    Opcode.remi: True,
    Opcode.xorr: False,
    Opcode.xori: True,
    Opcode.lshr: False,
    Opcode.lshi: True,
    Opcode.label: False,
    Opcode.forward: False,
    Opcode.link: False,
    Opcode.patch: False,
    Opcode.patch_at: False,
    Opcode.bltr: False,
    Opcode.blti: True,
    Opcode.bgtr: False,
    Opcode.bgti: True,
    Opcode.beqr: False,
    Opcode.beqi: True
}

syscall_funs = ["clock", "IsDebuggerPresent", "UnsetHwBreakpoints"]

#           natarg0       natarg1       natarg2           natarg3     natarg4  
inf_list = ["&VmHandler", "MagicBytes", "MagicBytesLen?", "Key120",   "Key0F0"]
#        =  0x6d6537f0    random addr   0xe5              0x6d709120  0x6d7090f0

comment_map = {
    Opcode.s_init: "init({0})",
    Opcode.s_execute: "return r{0} && start execution",
    Opcode.s_mov_func_inf: "r{0} = natarg{1}",
    Opcode.s_stxi_local: "todo",
    Opcode.s_ldxi_local: "r{1} = arg{0}",
    Opcode.s_call_sysfun: "{0}()", # exception for syscall_funs
    Opcode.s_finishi_sysfun: "{0}()",
    Opcode.prepare: "prepare next finish call",
    Opcode.pushargi: "todo",
    Opcode.pushargr: "todo",
    Opcode.reti: "return {0}",
    Opcode.retr: "return r{0}",
    Opcode.retval_l: "return value -> r{0}",
    Opcode.movr: "r{0} = r{1}",
    Opcode.movi: "r{0} = {3}",
    Opcode.ldr_l: "r{0} = *r{1} // long",
    Opcode.ldr_ui: "r{0} = *r{1} // uint",
    Opcode.ldxr_uc: "r{0} = *(r{1}+r{2}) // uchar",
    Opcode.str_l: "*r{0} = r{1} // long",
    Opcode.str_i: "*r{0} = r{1} // int",
    Opcode.stxr_c: "*(r{0}+r{1}) = r{2} // char",
    Opcode.addr: "r{0} += r{1}",
    Opcode.addi: "r{0} += {3}",
    Opcode.subr: "r{0} -= r{1}",
    Opcode.subi: "r{0} -= {3}",
    Opcode.mulr: "r{0} *= r{1}",
    Opcode.muli: "r{0} *= {3}",
    Opcode.divr: "r{0} /= r{1}",
    Opcode.divi: "r{0} /= {3}",
    Opcode.remr: "r{0} %= r{1}",
    Opcode.remi: "r{0} %= {3}",
    Opcode.xorr: "r{0} ^= r{1}",
    Opcode.xori: "r{0} ^= {3}",
    Opcode.lshr: "r{0} <<= r{1}",
    Opcode.lshi: "r{0} <<= {3}",
    Opcode.label: "label[{0}]",
    Opcode.forward: "forward {0}",
    Opcode.link: "link label[{0}]",
    Opcode.patch: "goto label[{0}]",
    Opcode.patch_at: "if c{0} -> goto label[{1}]",
    Opcode.bltr: "c{0} = r{1} < r{2}",
    Opcode.blti: "c{0} = r{1} < {3}",
    Opcode.bgtr: "c{0} = r{1} > r{2}",
    Opcode.bgti: "c{0} = r{1} > {3}",
    Opcode.beqr: "c{0} = r{1} == r{2}",
    Opcode.beqi: "c{0} = r{1} == {3}"
}

class PAVMInstruction:
    def __init__(self, opcode:Opcode, op0, op1, op2, opi):
        self.opcode = opcode
        self.op0 = op0
        self.op1 = op1
        self.op2 = op2
        self.opi = opi

class PAVMSim:
    GENERAL_MEM_ADDR = 0x000000
    CODE_ADDR        = 0x100000
    INP_BYTES_ADDR   = 0x200000
    KEY_120_ADDR     = 0x300000
    KEY_0F0_ADDR     = 0x400000
    LAST_CLOCK_ADDR  = 0x500000
    BIN_BYTES_ADDR   = 0x600000

    def __init__(self, binary_bytes, fun_offset, inp_bytes, funs, code):
        self.binary_bytes = binary_bytes
        self.binary_fun_offset = fun_offset # native arg 0
        self.inp_bytes = inp_bytes # native args 1 and 2 (2 is size) this is the key being decrypted
        self.funs = funs # syscall_funs
        self.key = [0]*0x50 # native arg 3
        self.iv = [0]*0x30 # native arg 4
        self.code = code # called arg 1 is end address of code (code+len(code))
        self.ip = 0
        self.bip = 0 # builder ip, separate from execution ip, called arg 0
        self.fun_ret_val = -1
        self.mem = []
        self.last_clock = [0]*8 # called arg 2 stores last clock() result (always 0 for us)
        self.registers = [0]*16
        self.cregisters = [0]*17 # might only be 16, idk
        self.dbg = False
    
    def reset(self):
        self.ip = 0
        self.mem = []
        for i in range(16):
            self.registers[i] = 0
        for i in range(17):
            self.cregisters[i] = 0
    
    def build(self):
        self.insts: list[PAVMInstruction] = []

        while True:
            this_inst = self.build_inst()
            self.insts.append(this_inst)
            if this_inst.opcode == Opcode.s_execute:
                break
        
        return self.bip >= len(self.code) - 4

    def build_inst(self):
        ip = self.bip

        d = self.read_int(ip)

        opcode = Opcode(d & 0xffff)
        opcode_name = str(opcode)[7:]

        operand_count = register_operand_count_map[opcode]
        operand_texts = ""

        operand0 = 0
        operand1 = 0
        operand2 = 0
        operandi = 0

        if operand_count == 1:
            operand0 = (d >> 16) & 0xff
            operand_texts = f"0x{operand0:02x}"
        elif operand_count == 2:
            operand0 = (d >> 16) & 0xff
            operand1 = d >> 24
            operand_texts = f"0x{operand0:02x} 0x{operand1:02x}"
        elif operand_count == 3:
            operand0 = (d >> 16) & 0xff
            operand1 = (d >> 24) & 0xf
            operand2 = d >> 28
            operand_texts = f"0x{operand0:02x} 0x{operand1:02x} 0x{operand2:02x}"

        if uses_imm_map[opcode]:
            dp = ip + 4
            operandi = self.read_int(dp)
        
        # debug only
        if opcode == Opcode.s_call_sysfun or opcode == Opcode.s_finishi_sysfun:
            comment = comment_map[opcode].format(syscall_funs[operand0])
        else:
            comment = comment_map[opcode].format(operand0, operand1, operand2, operandi)
        
        if uses_imm_map[opcode]:
            dbgText = f"{ip:08x} | {d:08x} | {opcode_name} {operand_texts} {{0x{operandi:02x}}} // {comment}"
        else:
            dbgText = f"{ip:08x} | {d:08x} | {opcode_name} {operand_texts} // {comment}"
        
        # print(dbgText)
        # ##################

        ip += size_map[opcode] * 4
        self.bip = ip

        return PAVMInstruction(opcode, operand0, operand1, operand2, operandi)
    
    # #############################
    
    def execute(self):
        while True:
            v = self.execute_single()
            if v != None:
                return v

    def execute_single(self):
        inst = self.insts[self.ip]
        code = inst.opcode
        do_not_increment_ip = False

        if code == Opcode.s_init:
            self.mem = [0]*(inst.op0 * 8)

            self.write_mem_u64(0, self.CODE_ADDR + self.bip)
            self.write_mem_u64(8, self.CODE_ADDR + len(self.code))
            self.write_mem_u64(16, self.LAST_CLOCK_ADDR) # last clock time
        
        elif code == Opcode.s_execute: # same as retr in execution
            return self.read_reg(inst.op0)
        
        elif code == Opcode.s_mov_func_inf:
            if inst.op1 == 0:
                self.write_reg(inst.op0, self.BIN_BYTES_ADDR + self.binary_fun_offset)
            elif inst.op1 == 1:
                self.write_reg(inst.op0, self.INP_BYTES_ADDR)
            elif inst.op1 == 2:
                self.write_reg(inst.op0, len(self.inp_bytes))
            elif inst.op1 == 3:
                self.write_reg(inst.op0, self.KEY_120_ADDR)
            elif inst.op1 == 4:
                self.write_reg(inst.op0, self.KEY_0F0_ADDR)
        
        elif code == Opcode.s_stxi_local:
            self.write_mem_u64(inst.op0 * 8, self.read_reg(inst.op1)) # untested
        
        elif code == Opcode.s_ldxi_local:
            self.write_reg(inst.op1, self.read_mem_u64(inst.op0 * 8))
        
        elif code == Opcode.s_call_sysfun:
            self.fun_ret_val = self.funs[inst.op0]()
        
        elif code == Opcode.s_finishi_sysfun:
            self.fun_ret_val = self.funs[inst.op0]()

        elif code == Opcode.prepare:
            if self.insts[self.ip + 1].opcode != Opcode.s_finishi_sysfun:
                raise Exception("next instruction after prepare must be finish")
            # don't do anything
        
        elif code == Opcode.pushargi:
            raise NotImplementedError("pushargi not supported")
        
        elif code == Opcode.pushargr:
            raise NotImplementedError("pushargr not supported")
        
        elif code == Opcode.pushargr:
            raise NotImplementedError("pushargr not supported")

        elif code == Opcode.reti:
            return inst.op0

        elif code == Opcode.retr:
            return self.read_reg(inst.op0)
        
        elif code == Opcode.retval_l:
            self.write_reg(inst.op0, self.fun_ret_val)
        
        elif code == Opcode.movr:
            self.write_reg(inst.op0, self.read_reg(inst.op1))
        
        elif code == Opcode.movi:
            self.write_reg(inst.op0, inst.opi)
        
        elif code == Opcode.ldr_l:
            self.write_reg(inst.op0, self.read_mem_u64(self.read_reg(inst.op1)))
        
        elif code == Opcode.ldr_ui:
            self.write_reg(inst.op0, self.read_mem_u32(self.read_reg(inst.op1)))
        
        elif code == Opcode.ldxr_uc:
            self.write_reg(inst.op0, self.read_mem_u8(self.read_reg(inst.op1) + self.read_reg(inst.op2)))
        
        elif code == Opcode.str_l:
            self.write_mem_u64(self.read_reg(inst.op0), self.read_reg(inst.op1))
        
        elif code == Opcode.str_i:
            self.write_mem_u32(self.read_reg(inst.op0), self.read_reg(inst.op1))
        
        elif code == Opcode.stxr_c:
            self.write_mem_u8(self.read_reg(inst.op0) + self.read_reg(inst.op1), self.read_reg(inst.op2))
        
        elif code == Opcode.addr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) + self.read_reg(inst.op1))
        
        elif code == Opcode.addi:
            self.write_reg(inst.op0, self.read_reg(inst.op0) + inst.opi)
        
        elif code == Opcode.subr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) - self.read_reg(inst.op1))
        
        elif code == Opcode.subi:
            self.write_reg(inst.op0, self.read_reg(inst.op0) - inst.opi)
        
        elif code == Opcode.mulr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) * self.read_reg(inst.op1))
        
        elif code == Opcode.muli:
            self.write_reg(inst.op0, self.read_reg(inst.op0) * inst.opi)
        
        elif code == Opcode.divr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) / self.read_reg(inst.op1))
        
        elif code == Opcode.divi:
            self.write_reg(inst.op0, self.read_reg(inst.op0) / inst.opi)
        
        elif code == Opcode.remr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) % self.read_reg(inst.op1))
        
        elif code == Opcode.remi:
            self.write_reg(inst.op0, self.read_reg(inst.op0) % inst.opi)
        
        elif code == Opcode.xorr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) ^ self.read_reg(inst.op1))
        
        elif code == Opcode.xori:
            self.write_reg(inst.op0, self.read_reg(inst.op0) ^ inst.opi)
            if self.dbg:
                exit(0)
        
        elif code == Opcode.lshr:
            self.write_reg(inst.op0, self.read_reg(inst.op0) << self.read_reg(inst.op1))
        
        elif code == Opcode.lshi:
            self.write_reg(inst.op0, self.read_reg(inst.op0) << inst.opi)
        
        elif code == Opcode.label:
            pass
        elif code == Opcode.forward:
            pass
        elif code == Opcode.link:
            pass
        
        elif code == Opcode.patch:
            raise NotImplementedError("patch not supported")
        
        elif code == Opcode.patch_at:
            if self.cregisters[inst.op0]:
                self.jmp_to_label(inst.op1)
                do_not_increment_ip = True
        
        elif code == Opcode.bltr:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) < self.read_reg(inst.op2)
        
        elif code == Opcode.blti:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) < inst.opi
        
        elif code == Opcode.bgtr:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) > self.read_reg(inst.op2)
        
        elif code == Opcode.bgti:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) > inst.opi
        
        elif code == Opcode.beqr:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) == self.read_reg(inst.op2)
        
        elif code == Opcode.beqi:
            self.cregisters[inst.op0] = self.read_reg(inst.op1) == inst.opi

        if not do_not_increment_ip:
            self.ip += 1
        
        return None
        

    def read_int(self, pos):
        code = self.code
        return code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16) | (code[pos + 3] << 24)
    
    # #############################

    def jmp_to_label(self, label_idx):
        i = 0
        for inst in self.insts:
            if inst.opcode == Opcode.label or inst.opcode == Opcode.link:
                if inst.op0 == label_idx:
                    self.ip = i
                    return
            i += 1
        
        raise Exception("jmp target not found")

    def read_mem_u64(self, addr):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        return arr[addr] | (arr[addr + 1] << 8) | (arr[addr + 2] << 16) | (arr[addr + 3] << 24) \
            | (arr[addr + 4] << 32) | (arr[addr + 5] << 40) | (arr[addr + 6] << 48) | (arr[addr + 7] << 56)

    def write_mem_u64(self, addr, d):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        arr[addr] = d & 0xff
        arr[addr + 1] = (d >> 8) & 0xff
        arr[addr + 2] = (d >> 16) & 0xff
        arr[addr + 3] = (d >> 24) & 0xff
        arr[addr + 4] = (d >> 32) & 0xff
        arr[addr + 5] = (d >> 40) & 0xff
        arr[addr + 6] = (d >> 48) & 0xff
        arr[addr + 7] = (d >> 56) & 0xff

    def read_mem_u32(self, addr):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        return arr[addr] | (arr[addr + 1] << 8) | (arr[addr + 2] << 16) | (arr[addr + 3] << 24)

    def write_mem_u32(self, addr, d):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        arr[addr] = d & 0xff
        arr[addr + 1] = (d >> 8) & 0xff
        arr[addr + 2] = (d >> 16) & 0xff
        arr[addr + 3] = (d >> 24) & 0xff
    
    def read_mem_u8(self, addr):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        return arr[addr]

    def write_mem_u8(self, addr, d):
        arr, off = self.get_mem_arr(addr)
        addr -= off
        arr[addr] = d & 0xff
    
    def get_mem_arr(self, addr):
        if self.GENERAL_MEM_ADDR <= addr and addr < self.CODE_ADDR:
            return (self.mem, self.GENERAL_MEM_ADDR)
        elif self.CODE_ADDR <= addr and addr < self.INP_BYTES_ADDR:
            return (self.code, self.CODE_ADDR)
        elif self.INP_BYTES_ADDR <= addr and addr < self.KEY_120_ADDR:
            return (self.inp_bytes, self.INP_BYTES_ADDR)
        elif self.KEY_120_ADDR <= addr and addr < self.KEY_0F0_ADDR:
            return (self.key, self.KEY_120_ADDR)
        elif self.KEY_0F0_ADDR <= addr and addr < self.LAST_CLOCK_ADDR:
            return (self.iv, self.KEY_0F0_ADDR)
        elif self.LAST_CLOCK_ADDR <= addr and addr < self.BIN_BYTES_ADDR:
            return (self.last_clock, self.LAST_CLOCK_ADDR)
        elif self.BIN_BYTES_ADDR <= addr:
            return (self.binary_bytes, self.BIN_BYTES_ADDR)
        else:
            raise Exception(f"memory address bad: {addr:02x}")
    
    def read_reg(self, idx):
        return self.registers[idx]
    
    def write_reg(self, idx, value):
        self.registers[idx] = value

# ###########################################

def clock():
    return 0

def IsDebuggerPresent():
    return 0

def UnsetHwBreakpoints():
    return 0

def get_file_bytes(file:io.BufferedReader, start, end):
    file.seek(start)
    return file.read(end - start)

def decrypt_with_vm(inp_bytes):
    print("executing vm... please be patient! (pls use pypy)")

    #file_path = sys.argv[1]
    file_path = "pytransform.pyd"
    f = open(file_path, "rb")

    # these need to be changed depending on your pyd!!
    binary_bytes = bytearray(get_file_bytes(f, 0x400, 0x81a00))
    fun_offset = 0x52bf0 - 0x400
    funs = [clock, IsDebuggerPresent, UnsetHwBreakpoints]
    code = bytearray(get_file_bytes(f, 0x83400, 0x83400 + 0x17985*4+4))

    f.close()

    sim = PAVMSim(binary_bytes, fun_offset, bytearray(inp_bytes), funs, code)
    i = 0
    while True:
        hit_end = sim.build()

        if hit_end:
            print("hit code end!")
            return (sim.key, sim.iv)
        
        err_code = sim.execute()
        if err_code != 0:
            raise Exception(f"vm failed a check or something... err code: {err_code}")
        
        sim.reset()
        i += 1
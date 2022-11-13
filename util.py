# used to unscramble python pyc opcodes
def get_zoombie(key, iv):
    key_sum = key[0] + key[3] + key[16] + key[28] + key[38] + key[39] + key[52] + key[55] + key[68]
    iv_sum = iv[2] + iv[6] + iv[12] + iv[16] + iv[20] + iv[21]
    return (key_sum + iv_sum) & 0xff

def read_mem_u32(arr, addr):
    return arr[addr] | (arr[addr + 1] << 8) | (arr[addr + 2] << 16) | (arr[addr + 3] << 24)

def read_mem_u32_le(arr, addr):
    return arr[addr + 3] | (arr[addr + 2] << 8) | (arr[addr + 1] << 16) | (arr[addr] << 24)

def write_mem_u32(arr, addr, d):
    arr[addr] = d & 0xff
    arr[addr + 1] = (d >> 8) & 0xff
    arr[addr + 2] = (d >> 16) & 0xff
    arr[addr + 3] = (d >> 24) & 0xff

def win_filename_rep(p:str):
    p = p.replace("<", "_")
    p = p.replace(">", "_")
    p = p.replace(":", "_")
    p = p.replace("\"", "_")
    p = p.replace("/", "_")
    p = p.replace("\\", "_")
    p = p.replace("|", "_")
    p = p.replace("?", "_")
    p = p.replace("*", "_")
    return p
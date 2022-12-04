from util import read_mem_u32, write_mem_u32
from Crypto.Cipher import DES3, AES
from Crypto.Util import Counter
import subprocess
import base64

def decrypt_des(blob, key, iv, inline):
    if not inline:
        # clone input arrays so the originals aren't modified
        key = bytearray(key)
        iv = bytearray(iv)

        for i in range(24):
            key[23-i] ^= ((i * i) + 3) & 0xff
        for i in range(8):
            iv[7-i] ^= ((i * i) + 3) & 0xff

        key = bytes(key)[:24]
        iv = bytes(iv)[:8]

    cipher = DES3.new(key, DES3.MODE_ECB)
    kk = cipher.encrypt(iv) # lmao encrypt

    out = [0]*len(blob)
    
    blob_pos = 0
    seg_pos = 0
    byte_counter = 0
    seg = [0]*8
    while blob_pos < len(blob):
        if byte_counter == 8:
            kk = cipher.encrypt(bytes(seg))
            seg_pos = 0
            byte_counter = 1
        else:
            seg_pos = byte_counter
            byte_counter += 1
        
        seg[seg_pos] = blob[blob_pos]
        out[blob_pos] = kk[seg_pos] ^ blob[blob_pos]
        blob_pos += 1

    return out

def decrypt_buffer_inline(blob):
    blob_chop = blob[0x20:]
    key = bytes(blob[:0x18])
    first_enc = bytes(blob[0x18:0x20])
    return decrypt_buffer(blob_chop, key, first_enc, True)

def decrypt_buffer(blob, key, iv, inline=False):
    unprotected_blob = decrypt_des(blob, key, iv, inline)
    
    if len(unprotected_blob) > 1:
        unprotected_blob[0] = ((~unprotected_blob[0]) & 0xff) ^ unprotected_blob[-1]
    else:
        unprotected_blob[0] = (~unprotected_blob[0]) & 0xff

    for i in range(1, len(unprotected_blob)):
        unprotected_blob[i] ^= unprotected_blob[i - 1]
    
    return unprotected_blob

def decrypt_buffer_basic_xor(blob, key, mul_plus=True):
    if mul_plus:
        key = bytearray(key)

        for i in range(24):
            key[i] ^= ((i * i) + 3) & 0xff
    
    new_blob = bytearray(blob)
    for i in range(0, len(new_blob)):
        new_blob[i] = new_blob[i] ^ key[i % len(key)]
    
    return new_blob

def decrypt_buffer_block(data, key, armor_key, minus):
    new_data = bytearray(data)

    key4_a1 = read_mem_u32(key, 0x00)
    key4_a2 = read_mem_u32(armor_key, 0x00)
    key4_a = key4_a1 ^ key4_a2

    key4_b1 = read_mem_u32(key, 0x04)
    key4_b2 = read_mem_u32(armor_key, 0x04) - 0xb35
    key4_b = key4_b1 ^ key4_b2

    key4_c1 = read_mem_u32(key, 0x08)
    key4_c2 = read_mem_u32(armor_key, 0x08) + 0xd6ae
    key4_c = key4_c1 ^ key4_c2

    key4_d1 = read_mem_u32(key, 0x0c)
    key4_d2 = read_mem_u32(armor_key, 0x0c) + 0xe9c3
    key4_d = key4_d1 ^ key4_d2

    key4_e = read_mem_u32(key, 0x10)
    key4_f = read_mem_u32(key, 0x14)

    key4 = [key4_a, key4_b, key4_c, key4_d, key4_e, key4_f]

    size = len(data)

    if minus:
        for i in range(size >> 2):
            dec_value = (read_mem_u32(new_data, i * 4) - 0xdd15) ^ key4[i % 6]
            write_mem_u32(new_data, i * 4, dec_value)
    else:
        for i in range(size >> 2):
            dec_value = (read_mem_u32(new_data, i * 4) ^ key4[i % 6]) + 0xdd15
            write_mem_u32(new_data, i * 4, dec_value)
    
    return new_data

def decrypt_ctr(data, key, armor_key):
    key4_a1 = read_mem_u32(key, 0x00)
    key4_a2 = read_mem_u32(armor_key, 0x00)
    key4_a = key4_a1 ^ key4_a2

    key4_b1 = read_mem_u32(key, 0x04)
    key4_b2 = read_mem_u32(armor_key, 0x04) - 0xf275
    key4_b = key4_b1 ^ key4_b2

    key4_c1 = read_mem_u32(key, 0x08)
    key4_c2 = read_mem_u32(armor_key, 0x08) + 0xb0b0
    key4_c = key4_c1 ^ key4_c2

    key4_d1 = read_mem_u32(key, 0x0c)
    key4_d2 = read_mem_u32(armor_key, 0x0c) + 0xcd59
    key4_d = key4_d1 ^ key4_d2
    
    key4_mem = [0]*16
    write_mem_u32(key4_mem, 0x00, key4_a)
    write_mem_u32(key4_mem, 0x04, key4_b)
    write_mem_u32(key4_mem, 0x08, key4_c)
    write_mem_u32(key4_mem, 0x0c, key4_d)

    cntr = Counter.new(nbits=128, initial_value=int.from_bytes(bytes(armor_key), "little"), little_endian=True)
    cipher = AES.new(bytes(key4_mem), AES.MODE_CTR, counter=cntr)
    new_data = cipher.decrypt(data)

    return new_data
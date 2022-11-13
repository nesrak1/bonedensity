#include <stdio.h>
#include <string.h>

#include <tomcrypt.h>

// compile with gcc tomcrypt_ctr.c -o tomcrypt_ctr -ltomcrypt -ltommath
int main(int argc, char** argv)
{
    char* data_b64 = argv[1];
    char* key_b64 = argv[2];
    char* iv_b64 = argv[3];
    
    char* ignoreEnd;
    int data_len = strtol(argv[4], &ignoreEnd, 10);
    int key_len = strtol(argv[5], &ignoreEnd, 10);
    int iv_len = strtol(argv[6], &ignoreEnd, 10);
    
    int data_b64_len = strlen(data_b64);
    int key_b64_len = strlen(key_b64);
    int iv_b64_len = strlen(iv_b64);
    
    unsigned char* data = malloc(data_len);
    unsigned char* undata = malloc(data_len);
    unsigned char* key = malloc(key_len);
    unsigned char* iv = malloc(iv_len);
    unsigned long ignoreLen;
    ignoreLen = data_len;
    base64_decode(data_b64, data_b64_len, data, &ignoreLen);
    ignoreLen = key_len;
    base64_decode(key_b64, key_b64_len, key, &ignoreLen);
    ignoreLen = iv_len;
    base64_decode(iv_b64, iv_b64_len, iv, &ignoreLen);
    
    register_cipher(&aes_desc);
    
    symmetric_CTR ctr;
    int err = ctr_start(find_cipher("aes"), iv, key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr);
    if (err == CRYPT_OK) {
        int err2 = ctr_decrypt(data, undata, data_len, &ctr);
        if (err2 == CRYPT_OK) {
            char* out_data = (char*)malloc(data_b64_len+1);
            out_data[data_b64_len] = '\0';
            char* undata2 = undata;
            ignoreLen = data_b64_len+1;
            base64_encode(undata2, data_len, out_data, &ignoreLen);
            printf("%s\n", out_data);
        }
    } else {
        printf("err: %u\n", err);    
    }
	
	// freeing memory is for noobs

    return 0;
}
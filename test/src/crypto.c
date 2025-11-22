#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>     // usleep, fsync
#include <stdint.h>     // uint64_t
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h> // SHA256 사용을 위해 추가
#include <arpa/inet.h>   // Big-Endian/Little-Endian 변환을 위해 추가

#define CHUNK_SIZE 4096
#define WRITE_DELAY_US 10000 // 0.01초

// 키 (고정 - 이것은 RED팀이 관리하는 비밀키이므로 고정이어도 됨)
static const unsigned char aes_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
}

/**
 * 파일 경로를 이용해 고유한 16바이트 IV 생성
 * - 저장할 필요 없음 (경로만 알면 언제든 다시 계산 가능)
 * - 파일마다 다른 IV가 생성됨
 */
void generate_iv_from_path(const char *filepath, unsigned char *iv_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 32바이트
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, filepath, strlen(filepath));
    SHA256_Final(hash, &sha256);

    // 해시 결과의 앞 16바이트를 IV로 사용
    memcpy(iv_out, hash, 16);
}


/**
 * PID 홉핑을 위한 "Stateless Worker" 함수
 * - Manager로부터 (path, offset, write_count, mode)를 받아 처리
 * @param mode 0 (Encrypt) 또는 1 (Decrypt)
 */
static int process_chunk_range(const char *filepath, long start_offset, int chunks_to_write, int mode) {
    FILE *fp = fopen(filepath, "r+b");
    if (!fp) {
        perror("fopen (r+b)");
        return -1; 
    }

    // 1. 시작 IV 계산 (암/복호화 동일)
    unsigned char starting_iv[16];
    generate_iv_from_path(filepath, starting_iv); 
    
    uint64_t block_counter = start_offset / 16;
    if (block_counter > 0) {
        uint64_t *counter_ptr = (uint64_t*)(starting_iv + 8);
        uint64_t host_counter = be64toh(*counter_ptr);  // Big-Endian -> Host-Endian
        host_counter += block_counter;  
        *counter_ptr = htobe64(host_counter);  // Host-Endian -> Big-Endian
    }

    // 2. OpenSSL 컨텍스트 단 한번 초기화
    EVP_CIPHER_CTX *ctx;
    int ret = -1; // 실패 기본값
    int out_len, final_len;
    unsigned char in_buf[CHUNK_SIZE];
    unsigned char out_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) { 
        fclose(fp);
        return -1; 
    }

    // --- mode에 따라 Init 함수 분기 ---
    if (mode == 0) { // ENCRYPT
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, starting_iv)) {
            goto cleanup;
        }
    } else { // DECRYPT
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, starting_iv)) {
            goto cleanup;
        }
    }
    // ------------------------------------------

    // 3. 시작 위치로 이동
    if (fseek(fp, start_offset, SEEK_SET) != 0) {
        goto cleanup;
    }

    // 4. 지정된 횟수만큼 "Update"만 반복
    for (int i = 0; i < chunks_to_write; i++) {
        long current_pos = ftell(fp);
        int read_len = fread(in_buf, 1, CHUNK_SIZE, fp);
        if (read_len <= 0) break; // 파일 끝

        // mode 에 따라 EncryptUpdate / DecryptUpdate 분기
        if (mode == 0) { // ENCRYPT
            if (1 != EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, read_len)) {
                handle_openssl_errors();
                break;
            }
        } else {         // DECRYPT
            if (1 != EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, read_len)) {
                handle_openssl_errors();
                break;
            }
        }
        
        fseek(fp, current_pos, SEEK_SET);
        fwrite(out_buf, 1, out_len, fp);
        fflush(fp); 
        
        usleep(WRITE_DELAY_US);
    }
    
    // 5. 마무리 (컨텍스트 정리)
    if (mode == 0) { // ENCRYPT
        if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &final_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
    } else { // DECRYPT
        if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &final_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
    }
    
    ret = 0; // 성공

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    fsync(fileno(fp));
    fclose(fp);
    return ret;
}



// === main.c에서 사용 가능한 public 래퍼 함수 ===

int encrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write) {
    // mode = 0 (Encrypt)
    return process_chunk_range(filepath, start_offset, chunks_to_write, 0);
}

int decrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write) {
    // mode = 1 (Decrypt)
    return process_chunk_range(filepath, start_offset, chunks_to_write, 1);
}


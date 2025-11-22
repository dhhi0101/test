#ifndef CRYPTO_H
#define CRYPTO_H


int encrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write);
int decrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write);


#endif
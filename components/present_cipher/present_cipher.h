#ifndef PRESENT_CIPHER_H
#define PRESENT_CIPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRESENT_KEY_SIZE_BYTES   10
#define PRESENT_BLOCK_SIZE_BYTES 8

int present_init(const uint8_t *key);
int present_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext);
int present_decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext);
int present_encrypt_ecb(const uint8_t *plaintext, size_t length, uint8_t *ciphertext);
int present_decrypt_ecb(const uint8_t *ciphertext, size_t length, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif // PRESENT_CIPHER_H
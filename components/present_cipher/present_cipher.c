#include "present_cipher.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG = "PRESENT_CIPHER";

static const uint8_t S_BOX[16] = {
    0xC, 0x5, 0x6, xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 00x8, 0x4, 0x7, 0x1, 0x2
};

static const uint8_t P_BOX[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

static uint8_t s_secret_key[PRESENT_KEY_SIZE_BYTES];
static uint8_t s_round_keys[32][PRESENT_BLOCK_SIZE_BYTES];

static uint64_t rotate_left_64(uint64_t value, int shift) {
    return (value << shift) | (value >> (64 - shift));
}

static void generate_round_keys(void) {
    uint64_t key_high = 0;
    uint64_t key_low = 0;

    for (int i = 0; i < 8; i++) {
        key_high = (key_high << 8) | s_secret_key[i];
    }
    for (int i = 8; i < PRESENT_KEY_SIZE_BYTES; i++) {
        key_low = (key_low << 8) | s_secret_key[i];
    }

    for (int round = 0; round < 32; round++) {
        uint64_t round_key = key_high;
        for (int i = 0; i < PRESENT_BLOCK_SIZE_BYTES; i++) {
            s_round_keys[round][i] = (round_key >> (56 - i * 8)) & 0xFF;
        }
        key_high = rotate_left_64(key_high, 61);
        uint8_t temp = key_low >> 3;
        key_low = (key_low << 61) | temp;
    }
}

static uint64_t apply_sbox(uint64_t block) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (block >> (60 - i * 4)) & 0xF;
        result = (result << 4) | S_BOX[nibble];
    }
    return result;
}

static uint64_t apply_pbox(uint64_t block) {
    uint64_t result = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t bit = (block >> (63 - i)) & 1;
        result |= (bit << (63 - P_BOX[i]));
    }
    return result;
}

int present_init(const uint8_t *key) {
    if (key == NULL) {
        ESP_LOGE(TAG, "Secret key pointer is NULL.");
        return -1;
    }
    memcpy(s_secret_key, key, PRESENT_KEY_SIZE_BYTES);
    generate_round_keys();
    ESP_LOGI(TAG, "PRESENT cipher initialized with an 80-bit key.");
    return 0;
}

int present_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext) {
    if (plaintext == NULL || ciphertext == NULL) return -1;

    uint64_t state = 0;
    for (int i = 0; i < PRESENT_BLOCK_SIZE_BYTES; i++) {
        state = (state << 8) | plaintext[i];
    }

    for (int round = 0; round < 31; round++) {
        uint64_t round_key = 0;
        for (int i = 0; i < PRESENT_BLOCK_SIZE_BYTES; i++) {
            round_key = (round_key << 8) | s_round_keys[round][i];
        }
        state ^= round_key;
        state = apply_sbox(state);
        state = apply_pbox(state);
    }

    uint64_t round_key = 0;
    for (int i = 0; i < PRESENT_BLOCK_SIZE_BYTES; i++) {
        round_key = (round_key << 8) | s_round_keys[31][i];
    }
    state ^= round_key;

    for (int i = 0; i < PRESENT_BLOCK_SIZE_BYTES; i++) {
        ciphertext[i] = (state >> (56 - i * 8)) & 0xFF;
    }
    return 0;
}

int present_decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext) {
    if (ciphertext == NULL || plaintext == NULL) return -1;
    memcpy(plaintext, ciphertext, PRESENT_BLOCK_SIZE_BYTES);
    ESP_LOGW(TAG, "Decryption is a placeholder in this version.");
    return 0;
}

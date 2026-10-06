#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

/*

Plaintext (total 21 characters): This is a top secret.
Ciphertext (in hex format):
5eb3f87efd1a883a1ee0a129e18a27ced3a7e31a8fa77bf546f2741d5435
814b
IV (in hex format): 010203040506070809000a0b0c0
*/

int main() {
    // had to change to the version from the offical SEED site
    // thank 0you to Caroline Lewis on our discord 
unsigned char ciphertext[] = {
    0x76,0x4a,0xa2,0x6b,0x55,0xa4,0xda,0x65,
    0x4d,0xf6,0xb1,0x9e,0x4b,0xce,0x00,0xf4,
    0xed,0x05,0xe0,0x93,0x46,0xfb,0x0e,0x76,
    0x25,0x83,0xcb,0x7d,0xa2,0xac,0x93,0xa2
};
unsigned char iv[] = {
    0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x99,
    0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11
};
    FILE *f = fopen("words.txt", "r");
    char word[32];

    while (fgets(word, sizeof(word), f)) {
        word[strcspn(word, "\n")] = 0;

        // build 16-byte key padded with '#'
        unsigned char key[16];
        if (strlen(word) > sizeof(key)) continue;
        memset(key, '#', 16);
        memcpy(key, word, strlen(word));

        // decrypt
        unsigned char out[64];
        int len1, len2;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, out, &len1, ciphertext, 32);
        EVP_DecryptFinal_ex(ctx, out + len1, &len2);
        EVP_CIPHER_CTX_free(ctx);

        // if we found the bytes and they match the plaintext, we found the key
        if (memcmp(out, "This is a top secret.", 21) == 0) {
            printf("Key found: %s\n", word);
            return 0;

            // its SYRACUSE!
        }
    }
    printf("Not found\n");
    return 0;
}
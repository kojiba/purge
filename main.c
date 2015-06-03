/*
 *  __________ ____ _____________  ___________________
 *  \______   \    |   \______   \/  _____/\_   _____/
 *   |     ___/    |   /|       _/   \  ___ |    __)_
 *   |    |   |    |  / |    |   \    \_\  \|        \
 *   |____|   |______/  |____|_  /\______  /_______  /
 *                            \/        \/        \/
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "purge.h"
#include "evasion.h"

#define initRClock()                                      clock_t tic = clock(); \
                                                          clock_t diff = 0, toc = 0;

#define tickRClock()                                      toc = clock(); \
                                                          diff = toc - tic; \
                                                          tic = clock(); \
                                                          printf("Elapsed: %f seconds\n", (double)(diff) / CLOCKS_PER_SEC);

#define forAll(iterator, count) for(iterator = 0; iterator < (count); ++iterator)

#define byteToBinaryPatern "%d%d%d%d%d%d%d%d "

#define byteToBinary(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0)

void printByteArrayInBin(const uint8_t *array, size_t size) {
    size_t iterator;
    forAll(iterator, size) {
        if (iterator % 8 == 0 && iterator != 0) {
            printf("\n");
        }
        printf(byteToBinaryPatern, byteToBinary(array[size - iterator - 1]));
    }
    printf("\n");
}


void printByteArrayInHex(const uint8_t *array, size_t size) {
    size_t iterator;
    for(iterator = 0; iterator <  size; ++iterator) {
        if (iterator % 32 == 0 && iterator != 0) {
            printf("\n");
        }
        printf("%02X ", array[iterator]);
    }
    printf("\n");
}

#define nil ((void*)0)
typedef uint8_t byte;

void* encryptPurgeEvasion(const void *text, uint64_t size, uint64_t key[8], uint64_t *cryptedSize) { // key changed and data not
    size_t   iterator;
    uint8_t *textTemp    = nil;
    size_t   totalSize   = size + sizeof(uint64_t);
    size_t   cipherCount = totalSize / purgeBytesCount;
    size_t   addition    = totalSize % purgeBytesCount;

    uint64_t keyTemp[8];

    if(addition != 0) {
        totalSize += purgeBytesCount - addition;
        ++cipherCount;
    }

    textTemp = malloc(totalSize);

    if(textTemp != nil) {
        *cryptedSize = 0;

        memcpy(textTemp, &size, sizeof(uint64_t));       // add size in front
        memcpy(textTemp + sizeof(uint64_t), text, size); // copy other text

        if (addition != 0) { // add some zeros if needed
            memset(textTemp + size + sizeof(uint64_t), 0, purgeBytesCount - addition);
        }

        forAll(iterator, cipherCount) {
            evasionHash(key);
            memcpy(keyTemp, key, purgeBytesCount);
            purgeEncrypt((uint64_t *) (textTemp + iterator * purgeBytesCount), keyTemp);
            memset(keyTemp, 0, purgeBytesCount);
        }
        *cryptedSize = totalSize; // store
    }
    return textTemp;
}

void* decryptPurgeEvasion(const void *text, uint64_t size, uint64_t key[8], uint64_t *encryptedSize) { // key changed and data not
    size_t   iterator;
    uint8_t *textTemp    = nil,
            *plainText   = nil;
    size_t   cipherCount = size / purgeBytesCount;
    uint64_t sizeOfText;
    uint64_t keyTemp[8];

    if(size % purgeBytesCount) {
        printf("Bad data size. Must be multiple of 64. Data size in bytes\n");
        return nil;
    }

    textTemp = malloc(size);

    if(textTemp != nil) {
        *encryptedSize = 0;
        memcpy(textTemp, text, size); // add size in front

        forAll(iterator, cipherCount) {
            evasionHash(key);
            memcpy(keyTemp, key, purgeBytesCount);
            purgeDecrypt((uint64_t *) (textTemp + iterator * purgeBytesCount), keyTemp);
            memset(keyTemp, 0, purgeBytesCount);
        }

        // get size
        memcpy(&sizeOfText, textTemp, sizeof(uint64_t));
        plainText = malloc(sizeOfText);
        if(plainText != nil) {
            memcpy(plainText, textTemp + sizeof(uint64_t), sizeOfText);
            *encryptedSize = sizeOfText; // store
        }
        free(textTemp);
    }
    return plainText;
}

int main(int argc, const char *argv[]) {

    uint64_t key[8] = {}, data[8] = {};
    uint64_t size;

    char *stringToEncrypt = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \n"
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n"
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut\n"
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in\n"
            "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint\n"
            "occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit\n"
            "anim id est laborum.";

    uint64_t stringLength = strlen(stringToEncrypt) + 1;

    printf("size : %llu\n", stringLength);


    memcpy(key, "Hello world!", sizeof("Hello world!"));
    memcpy(data, key, purgeBytesCount);
    printf("Key:\n");
    printByteArrayInHex((const byte *) key, purgeBytesCount);

    printf("Data:\n");
    printByteArrayInHex((const uint8_t *) stringToEncrypt, stringLength);

    printf("Cipher Text:\n");
    byte *cipherText = encryptPurgeEvasion(stringToEncrypt, stringLength, key, &size);
    printByteArrayInHex(cipherText, size);

    printf("Key:\n");
    memset(key, 0, purgeBytesCount);
    memcpy(key, "Hello world!", sizeof("Hello world!"));
    printByteArrayInHex((const byte *) key, purgeBytesCount);

    printf("Decipher Text:\n");
    byte *decipherText = decryptPurgeEvasion(cipherText, size, key, &size);
    printf("%s", decipherText);

    free(cipherText);
    free(decipherText);

    return 0;
}
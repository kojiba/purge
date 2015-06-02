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


void printByteArrayInHex(const uint8_t *array, int size) {
    size_t iterator;
    for(iterator = 0; iterator <  size; ++iterator) {
        if (iterator % 32 == 0 && iterator != 0) {
            printf("\n");
        }
        printf("%02X ", array[iterator]);
    }
    printf("\n");
}

void* encryptPurgeEvasion(const void *text, size_t size, uint64_t key[8]) { // key changed and data not
    size_t iterator;
    uint8_t *textTemp = 0;
    size_t addition = size % purgeBytesCount;
    size_t cipherCount = size / purgeBytesCount;
    uint64_t keyTemp[8];

    if(addition != 0) {
        textTemp = malloc(size + purgeBytesCount - addition);
        memcpy(textTemp, text, size);
        memset(textTemp, 0, purgeBytesCount - addition); // add some zeros
        ++cipherCount;
    } else {
        textTemp = malloc(size);
        memcpy(textTemp, text, size);
    }

    forAll(iterator, cipherCount) {
        evasionHash(key);
        memcpy(keyTemp, key, purgeBytesCount);
        purgeEncrypt((uint64_t*) (textTemp + iterator * purgeBytesCount), keyTemp);
        memset(keyTemp, 0, purgeBytesCount);
    }
    return textTemp;
}

int main() {
    size_t iterator;
    char *text = malloc(10);
    memcpy(text, "0123456789", 10);

    uint64_t key[8] = {};
    memcpy(key, "123456789012345678901234567890123456789012345678901234567890123", 64);

    char *encrypted = encryptPurgeEvasion(text, strlen(text), key);

    printByteArrayInHex((const uint8_t *) encrypted, 64);

    return 0;
}
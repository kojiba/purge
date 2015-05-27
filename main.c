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
#include "purge.h"

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

int main() {
    size_t iterator;
    uint64_t data[8] = {},
            key[8] = {}, data2[8] = {}, key2[8] = {};

//    printf("data : \n");
//    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);
//
//    printf("key : \n");
//    printByteArrayInHex((const uint8_t *) key, purgeBytesCount);
//
//    printf("ciphered : \n");
    initRClock();
//    purgeEncrypt(data, key);
//    tickRClock();
//    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);
//
//    data2[0] = 1;
//
//    printf("data2 : \n");
//    printByteArrayInHex((const uint8_t *) data2, purgeBytesCount);
//    printf("key : \n");
//    printByteArrayInHex((const uint8_t *) key, purgeBytesCount);
//
//    tickRClock();
//    purgeEncrypt(data2, key);
//    tickRClock();
//    printf("ciphered 2 : \n");
//    printByteArrayInHex((const uint8_t *) data2, purgeBytesCount);
//
//    printf("key2 : \n");
//    printByteArrayInHex((const uint8_t *) key2, purgeBytesCount);

    forAll(iterator, 1024) {
        tickRClock();
        purgeEncrypt(data, key);
        memset(key, 0, purgeBytesCount);
//        printByteArrayInHex((const uint8_t *) data, purgeBytesCount);
    }

//
//    printf("deciphered 2 : \n");
//    printByteArrayInHex((const uint8_t *) data2, purgeBytesCount);

    return 0;
}
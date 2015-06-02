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

int main() {
    size_t iterator;
    uint64_t data[8] = {},
            key[8] = {};

    initRClock();
    tickRClock();

//    forAll(iterator, 1024) {
//        tickRClock();
        printf("data : \n");
        printByteArrayInHex((const uint8_t *) data, evasionBytesCount);
        evasionHash(data);
        printf("hash : \n");
        printByteArrayInHex((const uint8_t *) data, evasionBytesCount);
        memset(data, 0, evasionBytesCount);
        data[0] = 1;
        printf("data : \n");
        printByteArrayInHex((const uint8_t *) data, evasionBytesCount);
        evasionHash(data);
        printf("hash : \n");
        printByteArrayInHex((const uint8_t *) data, evasionBytesCount);
//    }

    return 0;
}
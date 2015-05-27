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
#include "purge.h"

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
    uint64_t data[8] = {},
            key[8] = {}, data2[8] = {}, key2[8] = {};

    printf("data : \n");
    printByteArrayInHex((const uint8_t *) data, bytesCount);

    printf("key : \n");
    printByteArrayInHex((const uint8_t *) key, bytesCount);

    printf("ciphered : \n");
    purgeEncrypt(data, key);
    printByteArrayInHex((const uint8_t *) data, bytesCount);

    data2[0] = 1;

    printf("data2 : \n");
    printByteArrayInHex((const uint8_t *) data2, bytesCount);
    printf("key : \n");
    printByteArrayInHex((const uint8_t *) key, bytesCount);

    purgeEncrypt(data2, key);
    printf("ciphered 2 : \n");
    printByteArrayInHex((const uint8_t *) data2, bytesCount);

    printf("key2 : \n");
    printByteArrayInHex((const uint8_t *) key2, bytesCount);

    purgeDecrypt(data2, key2);
    printf("deciphered 2 : \n");
    printByteArrayInHex((const uint8_t *) data2, bytesCount);

    return 0;
}
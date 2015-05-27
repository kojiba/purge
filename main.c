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

int main() {
    uint8_t array[bytesCount] = {}, arrayReverse[256];

    uint64_t temp;

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

    printf("ciphered 2 : \n");
    purgeEncrypt(data2, key);
    printByteArrayInHex((const uint8_t *) data2, bytesCount);

    printf("key2 : \n");
    printByteArrayInHex((const uint8_t *) key2, bytesCount);

    printf("deciphered 2 : \n");
    purgeDecrypt(data2, key2);
    printByteArrayInHex((const uint8_t *) data2, bytesCount);


    // ------------------------------------------------ deciper

//    forAll(iterator, bytesCount) {
//        array[iterator] = (byte) iterator;
//    }
//    printByteArrayInHex(array, bytesCount);
//
//    rotateBytes(array, 3);
//
//    printByteArrayInHex(array, bytesCount);
//
//    reverseRotateBytes(array, 3);
//
//    printByteArrayInHex(array, bytesCount);


//    // checks
//    byte temp = array[10];
//    printf("Temp : %d\n", temp);
//    temp = arrayReverse[temp];
//    printf("Temp : %d\n", temp);
    return 0;
}
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
#include "PurgeEvasionUtils.h"

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

typedef uint8_t byte;

void cipherTestSimple() {
    uint64_t key[8] = {}, data[8] = {};

    printf("Data:\n");
    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);

    printf("Key:\n");
    printByteArrayInHex((const uint8_t *) key, purgeBytesCount);

    purgeEncrypt(data, key);
    printf("Ciphered:\n");
    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);

    memset(key, 0, purgeBytesCount);
    memset(data, 0, purgeBytesCount);
    data[0] = 1;
    printf("Data:\n");
    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);
    printf("Key:\n");
    printByteArrayInHex((const uint8_t *) key, purgeBytesCount);

    purgeEncrypt(data, key);
    printf("Ciphered 2:\n");
    printByteArrayInHex((const uint8_t *) data, purgeBytesCount);

}

void cipherTest() {
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

    printf("\n Chiper test --------------------------------\n");

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
    printf("decipher size : %llu\n", size);
    printf("%s", decipherText);


    free(cipherText);
    free(decipherText);
}

void hashTest() {
    uint64_t dest[8];

    char *stringToHash = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \n"
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n"
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut\n"
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in\n"
            "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint\n"
            "occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit\n"
            "anim id est laborum.";

                     // diff here | 1 bit
    char *stringToHash2 = "Lorem iqsum dolor sit amet, consectetur adipiscing elit, \n"
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n"
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut\n"
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in\n"
            "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint\n"
            "occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit\n"
            "anim id est laborum.";

    char *stringToHash3 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \n"
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n"
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut\n"
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in\n"
            "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint\n"
                       // diff here | 1 bit
            "occaecat cupidatat non qroident, sunt in culpa qui officia deserunt mollit\n"
            "anim id est laborum.";

    uint64_t stringLength = strlen(stringToHash);

    printf("\n hashTest --------------------------------\n");

    evasionHashData(stringToHash, stringLength, dest);
    printf("\nHash:\n");
    printByteArrayInHex((const byte *) dest, evasionBytesCount);

    memset(dest, 0, evasionBytesCount);

    printf("Hash 2:\n");
    evasionHashData(stringToHash2, stringLength, dest);
    printByteArrayInHex((const byte *) dest, evasionBytesCount);

    memset(dest, 0, evasionBytesCount);

    printf("Hash 3:\n");
    evasionHashData(stringToHash3, stringLength, dest);
    printByteArrayInHex((const byte *) dest, evasionBytesCount);
}

void simpleCollisionTest() {
    size_t iterator;
    uint64_t data[8] = {};

    printf("\n rand collision Test --------------------------------\n");

    forAll(iterator, 13) {
        memset((byte *) data, 0, evasionBytesCount);
        data[0] = iterator;
        evasionRand(data);
        printf("Hash %lu:\n", iterator);
        printByteArrayInHex((const byte *) data, evasionBytesCount);
    }
}

void optimisationTest(){
    byte array[purgeBytesCount] = {};
    byte key[purgeBytesCount] = {};


    printf("\n Optimisation Test --------------------------------\n");
    printByteArrayInHex(array, purgeBytesCount);

    byte cipherText[purgeBytesCount] = {};

    initRClock();
    purgeEncrypt((uint64_t *) array, (uint64_t *) key);
    tickRClock();
    printByteArrayInHex(array, purgeBytesCount);
    memset(key, 0, purgeBytesCount);

    tickRClock();
    purgeDecrypt((uint64_t *) array, (uint64_t *) key);
    tickRClock();
    printByteArrayInHex(array, purgeBytesCount);

    /* Etalon
     *
     * Encr Elapsed: 0.000053 seconds
       Decr Elapsed: 0.000085 seconds

     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       B8 FF E8 11 EB 46 0F FE 12 AE 7F 34 E7 7A 03 49 18 B8 F8 AA EA F4 D6 3D 1F A8 98 35 35 C7 5C 42
       91 42 7E 4C CF EA E4 30 56 6E 4B 28 19 4D D0 FA 72 55 FE DB 48 D5 79 FA 5A 1D 9B 47 10 9D E1 7E
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     */

    /* PURGE_DECRYPT_SPEEDUP
     *
     * Encr Elapsed: 0.000060 seconds
       Decr Elapsed: 0.000061 seconds

     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       B8 FF E8 11 EB 46 0F FE 12 AE 7F 34 E7 7A 03 49 18 B8 F8 AA EA F4 D6 3D 1F A8 98 35 35 C7 5C 42
       91 42 7E 4C CF EA E4 30 56 6E 4B 28 19 4D D0 FA 72 55 FE DB 48 D5 79 FA 5A 1D 9B 47 10 9D E1 7E
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     */
}

void crtTest(){
    byte array[purgeBytesCount] = {};
    byte key[purgeBytesCount] = {};

    size_t dieHardCount = 256;
    size_t iterator;

    forAll(iterator, dieHardCount) {
        array[0] = (byte) iterator;
        purgeEncrypt((uint64_t *) array, (uint64_t *) key);
        printByteArrayInHex(array, purgeBytesCount);
        memset(key, 0, purgeBytesCount);
        memset(array, 0, purgeBytesCount);
    }
}

int main(int argc, const char *argv[]) {
//
//    cipherTestSimple();
//    cipherTest();
//    hashTest();
//    simpleCollisionTest();
//    optimisationTest();
    crtTest();

    exit(0);
}
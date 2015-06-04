/**
 * PurgeEvasionUtils.h
 * Data cipher based on purge encryption
 * and evasion in mode pseudo-rand generator.
 * Data hash based on evasion
 * Author Kucheruavyu Ilya (kojiba@ro.ru)
 * 06/02/2015 Ukraine Kharkiv
 *  _         _ _ _
 * | |       (_|_) |
 * | | _____  _ _| |__   __ _
 * | |/ / _ \| | | '_ \ / _` |
 * |   < (_) | | | |_) | (_| |
 * |_|\_\___/| |_|_.__/ \__,_|
 *          _/ |
 *         |__/
 **/

#include "PurgeEvasionUtils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define nil ((void*)0)
#define forAll(iterator, count) for(iterator = 0; iterator < (count); ++iterator)

void* encryptPurgeEvasion(const void *text, uint64_t size, uint64_t key[8], uint64_t *cryptedSize) { // key changed and data not
    uint64_t  iterator;
    uint8_t  *textTemp     = nil;
    uint64_t  totalSize   = size + sizeof(uint64_t);
    uint64_t  cipherCount = totalSize / purgeBytesCount;
    uint64_t  addition    = totalSize % purgeBytesCount;

    uint8_t keyTemp[purgeBytesCount];

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
    uint64_t iterator;
    uint8_t *textTemp    = nil,
            *plainText   = nil;
    uint64_t cipherCount = size / purgeBytesCount;
    uint64_t sizeOfText;
    uint8_t keyTemp[purgeBytesCount];

    if(size % purgeBytesCount) {
        perror("Bad data size. Must be multiple of 64. Data size in bytes\n");
        return nil;
    }

    textTemp = malloc(size);

    if(textTemp != nil) {
        *encryptedSize = 0;
        memcpy(textTemp, text, size); // add size in front

        forAll(iterator, cipherCount) {
            evasionHash(key);
            memcpy(keyTemp, key, purgeBytesCount);
            purgeDecrypt((uint64_t *) (textTemp + iterator * purgeBytesCount), (uint64_t *) keyTemp);
            memset(keyTemp, 0, purgeBytesCount);
        }

        // get size
        memcpy((uint8_t*) &sizeOfText, textTemp, sizeof(uint64_t));
        plainText = malloc(sizeOfText);
        if(plainText != nil) {
            memcpy(plainText, textTemp + sizeof(uint64_t), sizeOfText);
            *encryptedSize = sizeOfText; // store
        }
        free(textTemp);
    }
    return plainText;
}

void evasionHashData(const void *text, uint64_t size, uint64_t *outputHash) {
    uint64_t iterator;
    uint64_t hashTemp[8] = {};
    uint8_t  half = evasionBytesCount / 2;
    uint64_t hashCount = size / half;
    uint64_t addition  = size % half;


    forAll(iterator, hashCount) {
        memcpy((uint8_t*) &hashTemp[0] + half, text + iterator * half, half);
        printf("%llu - %llu %llu %llu %llu %llu %llu %llu %llu\n",
               iterator, hashTemp[0], hashTemp[1], hashTemp[2], hashTemp[3],
                         hashTemp[4], hashTemp[5], hashTemp[6], hashTemp[7]);
        evasionHash(hashTemp);
    }

    if(addition) {
        memcpy((uint8_t*) hashTemp + half, text + hashCount * half, addition);
        memset((uint8_t*) hashTemp + half + addition, 0, half - addition);
        evasionHash(hashTemp);
    }
    // final
    memcpy(outputHash, hashTemp, evasionBytesCount);
}

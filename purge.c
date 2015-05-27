/**
 * purge.c
 * 512-bit block encryption algorithm
 * Author Kucheruavyu Ilya (kojiba@ro.ru)
 * 06/27/2015 Ukraine Kharkiv
 *  _         _ _ _
 * | |       (_|_) |
 * | | _____  _ _| |__   __ _
 * | |/ / _ \| | | '_ \ / _` |
 * |   < (_) | | | |_) | (_| |
 * |_|\_\___/| |_|_.__/ \__,_|
 *          _/ |
 *         |__/
 **/

#include "purge.h"
#include <string.h>
#include <stdio.h>


typedef uint8_t byte;

#define forAll(iterator, count) for(iterator = 0; iterator < (count); ++iterator)

// 64 circular shift (rotates)
#define rotateLeft(data,  shift) (((data) << shift) | ((data) >> (64 - shift)))
#define rotateRight(data, shift) (((data) >> shift) | ((data) << (64 - shift)))


#define sawSwap(array)     temp = array[7]; \
                       array[7] = array[2]; \
                       array[2] = array[5]; \
                       array[5] = array[0]; \
                       array[0] = temp; \
                           temp = 0

#define sawUnswap(array)     temp = array[0]; \
                         array[0] = array[5]; \
                         array[5] = array[2]; \
                         array[2] = array[7]; \
                         array[7] = temp; \
                             temp = 0

#define roundKeyXor(data, key) data[0] ^= key[0]; \
                               data[1] ^= key[1]; \
                               data[2] ^= key[2]; \
                               data[3] ^= key[3]; \
                               data[4] ^= key[4]; \
                               data[5] ^= key[5]; \
                               data[6] ^= key[6]; \
                               data[7] ^= key[7]

#define roundAmplification(sign)  key[0] sign= keyАmplification[0]; \
                                  key[1] sign= keyАmplification[1]; \
                                  key[2] sign= keyАmplification[2]; \
                                  key[3] sign= keyАmplification[3]; \
                                  key[4] sign= keyАmplification[4]; \
                                  key[5] sign= keyАmplification[5]; \
                                  key[6] sign= keyАmplification[6]; \
                                  key[7] sign= keyАmplification[7]

uint64_t substitute(uint64_t data, const byte *block) {
    union bytesTo64 {
        uint64_t number;
        byte bytes[8];
    };
    union bytesTo64 wrapper;

    wrapper.number = data;
    wrapper.bytes[0] = block[wrapper.bytes[0]];
    wrapper.bytes[1] = block[wrapper.bytes[1]];
    wrapper.bytes[2] = block[wrapper.bytes[2]];
    wrapper.bytes[3] = block[wrapper.bytes[3]];
    wrapper.bytes[4] = block[wrapper.bytes[4]];
    wrapper.bytes[5] = block[wrapper.bytes[5]];
    wrapper.bytes[6] = block[wrapper.bytes[6]];
    wrapper.bytes[7] = block[wrapper.bytes[7]];
    return wrapper.number;
}

void rotateBytes(byte *data, byte count) {
    if(count % bytesCount) {
        byte diff = (byte) (bytesCount - count);
        byte temp[bytesCount];
        memcpy(temp, data, count);
        memcpy(data, data + count, diff);
        memcpy(data + diff, temp, count);
        memset(temp, 0, bytesCount);
    }
}

void reverseRotateBytes(byte *data, byte count) {
    if(count % bytesCount) {
        byte temp[bytesCount];
        byte diff = (byte) (bytesCount - count);
        memcpy(temp, data + diff, count);
        memcpy(data + count, data, diff);
        memcpy(data, temp, count);
        memset(temp, 0, bytesCount);
    }
}

void roundKeyForStep(uint64_t key[8], uint8_t step) {
    byte iterator;
    uint64_t temp;
    forAll(iterator, step) {
        sawSwap(key);
        key[1] = substitute(key[1], substitutionBlock);
        key[3] = substitute(key[3], substitutionBlock);
        key[4] = substitute(key[4], substitutionBlock);
        key[6] = substitute(key[6], substitutionBlock);

        key[0] += keyАmplification[0];
        key[1] += keyАmplification[1];
        key[2] += keyАmplification[2];
        key[3] += keyАmplification[3];
        key[4] += keyАmplification[4];
        key[5] += keyАmplification[5];
        key[6] += keyАmplification[6];
        key[7] += keyАmplification[7];

        rotateBytes((byte *) key, (byte) (iterator % (bytesCount / 2) + 1));
    }
    memset(&iterator, 0, 1);
}

void decryptRoundKey(uint64_t key[8], uint8_t step) {
    byte iterator;
    uint64_t temp;
    for(iterator = (byte) (step - 1); iterator != 255; --iterator) {
        reverseRotateBytes((byte *) key, (byte) (iterator % (bytesCount / 2) + 1));

        key[0] -= keyАmplification[0];
        key[1] -= keyАmplification[1];
        key[2] -= keyАmplification[2];
        key[3] -= keyАmplification[3];
        key[4] -= keyАmplification[4];
        key[5] -= keyАmplification[5];
        key[6] -= keyАmplification[6];
        key[7] -= keyАmplification[7];

        key[1] = substitute(key[1], reverseSubstitutionBlock);
        key[3] = substitute(key[3], reverseSubstitutionBlock);
        key[4] = substitute(key[4], reverseSubstitutionBlock);
        key[6] = substitute(key[6], reverseSubstitutionBlock);

        sawUnswap(key);
    }
    memset(&iterator, 0, 1);
}

void purgeEncrypt(uint64_t data[8], uint64_t key[8]) {
    uint64_t temp;
    byte iterator;

    forAll(iterator, roundsCount) { // 63 rounds [0 : 62]
        // round
        data[0] = rotateLeft(data[0], 7);
        data[1] ^= palindromeMask;
        data[2] ^= palindromeMaskReverse;
        data[3] = rotateLeft(data[3], 13);

        data[4] += data[3];
        data[5] += data[0];
        data[6] += mask;
        data[7] += maskReverse;

        roundKeyForStep(key, (uint8_t) (iterator + 1));

        roundKeyXor(data, key);
        sawSwap(data);

        data[1] = substitute(data[1], substitutionBlock);
        data[3] = substitute(data[3], substitutionBlock);
        data[4] = substitute(data[4], substitutionBlock);
        data[6] = substitute(data[6], substitutionBlock);

        rotateBytes((byte *) data, (byte)(iterator % (bytesCount / 2) + 1));
    }

    memset(key, 0, bytesCount);
}

void purgeDecrypt(uint64_t data[8], uint64_t key[8]) {
    uint64_t temp;
    byte iterator;

    // get final key
    forAll(iterator, roundsCount) {
        roundKeyForStep(key, (uint8_t) (iterator + 1));
    }

    for(iterator = roundsCount - 1; iterator != 255; --iterator) {
        reverseRotateBytes((byte *) data, (byte)(iterator % (bytesCount / 2) + 1));

        data[1] = substitute(data[1], reverseSubstitutionBlock);
        data[3] = substitute(data[3], reverseSubstitutionBlock);
        data[4] = substitute(data[4], reverseSubstitutionBlock);
        data[6] = substitute(data[6], reverseSubstitutionBlock);

        sawUnswap(data);
        roundKeyXor(data, key);

        decryptRoundKey(key, (uint8_t) (iterator + 1));

        // round
        data[7] -= maskReverse;
        data[6] -= mask;
        data[5] -= data[0];
        data[4] -= data[3];

        data[3] = rotateRight(data[3], 13);
        data[2] ^= palindromeMaskReverse;
        data[1] ^= palindromeMask;
        data[0] = rotateRight(data[0], 7);
    }

    memset(key, 0, bytesCount);
}

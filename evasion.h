/**
 * evasion.h
 * 512-bit block pseudo-rand gen
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

#ifndef __EVASION_H__
#define __EVASION_H__

#include <stdint.h>

static const uint8_t evasionBytesCount  = 64;
static const uint8_t evasionRoundsCount = 17;

static const uint64_t evasionAmplificationConstants[8] = {
        0x1234567890123456, // zero diagonal some and
        0x0234567890123455, // make odd
        0x0034567890123455, // make odd
        0x0004567890123455, // make odd
        0x0000567890123456,
        0x0000067890123456,
        0x0000007890123456,
        0x0000000890123457  // make odd
};

static const uint8_t evasionSubstitutionBlock[256] = {
        0x36, 0x6F, 0x68, 0xA4, 0xB2, 0x5B, 0x0F, 0x41, 0x1E, 0x31, 0x2D, 0xA1, 0x33, 0x46, 0x63, 0x07,
        0x50, 0xB7, 0x47, 0xBB, 0xE3, 0xA3, 0x8D, 0x2E, 0x73, 0xF8, 0x51, 0xC7, 0xA5, 0x54, 0xC4, 0x04,
        0xE6, 0x3B, 0x5E, 0x0B, 0x38, 0x3C, 0x4A, 0xB4, 0x78, 0xDD, 0xD5, 0xCE, 0x3D, 0x3F, 0xAD, 0x98,
        0x92, 0x0D, 0xB0, 0x4D, 0x4E, 0x65, 0xCA, 0x95, 0x9C, 0x30, 0x8F, 0x56, 0xDF, 0x10, 0x52, 0xB6,
        0xED, 0x0A, 0x17, 0x58, 0x84, 0xD4, 0xAE, 0xF4, 0xE2, 0x2B, 0x70, 0xC6, 0xF7, 0x9F, 0x1F, 0xCC,
        0x61, 0xB1, 0xD3, 0x08, 0xF5, 0xD8, 0x55, 0x00, 0x32, 0x15, 0x24, 0xEF, 0xAC, 0x86, 0x75, 0x19,
        0x13, 0xE7, 0xAA, 0x5C, 0x20, 0x0E, 0x1B, 0x85, 0xE5, 0x01, 0xBC, 0x39, 0xF3, 0xB5, 0xFE, 0xFC,
        0xFD, 0x96, 0x12, 0x6D, 0x0C, 0xEC, 0x03, 0xD6, 0x2F, 0x89, 0xE0, 0x88, 0x21, 0xCF, 0x40, 0x82,
        0x06, 0x90, 0xD1, 0x6E, 0x9B, 0x64, 0x8B, 0x11, 0xA0, 0x23, 0x6B, 0x49, 0x76, 0xDA, 0x74, 0xDB,
        0x42, 0xE1, 0xA9, 0x60, 0xA6, 0xEB, 0xC8, 0x4F, 0x91, 0x69, 0x34, 0x81, 0xBD, 0x9A, 0x2C, 0x3E,
        0x1D, 0x2A, 0x7B, 0xBE, 0x05, 0x62, 0xD7, 0xC1, 0xA2, 0xAB, 0x72, 0x94, 0xFA, 0xFB, 0xD9, 0x57,
        0x6C, 0x35, 0xF9, 0xE9, 0xB8, 0x02, 0x4C, 0x9E, 0xDE, 0xBF, 0x87, 0x71, 0x28, 0x5F, 0xCB, 0xC5,
        0xE4, 0x5D, 0x16, 0x66, 0x27, 0xAF, 0xA7, 0x1C, 0xC9, 0xD2, 0x97, 0xF1, 0x1A, 0x26, 0xD0, 0x25,
        0x79, 0x7C, 0x8A, 0xBA, 0x59, 0x77, 0x5A, 0xF6, 0x83, 0xA8, 0x9D, 0x80, 0x48, 0x44, 0x14, 0x8E,
        0x18, 0x22, 0x37, 0x7F, 0xF0, 0xE8, 0xFF, 0x45, 0xF2, 0xB3, 0xC0, 0xEA, 0xDC, 0x67, 0x53, 0x7D,
        0xB9, 0xEE, 0x99, 0x7E, 0x6A, 0x43, 0x29, 0x93, 0x09, 0x7A, 0xCD, 0xC3, 0x4B, 0x3A, 0xC2, 0x8C,
};

void evasionHash(uint64_t data[8]); // data will be changed

#endif /*__EVASION_H__*/

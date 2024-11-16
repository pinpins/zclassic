// Copyright (c) 2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "script/script_flags.h"
#include "script/sigencoding.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sigencoding_tests, BasicTestingSetup)

static valtype SignatureWithHashType(valtype vchSig, SigHashType sigHash) {
    vchSig.push_back(static_cast<uint8_t>(sigHash.getRawSigHashType()));
    return vchSig;
}

static void CheckSignatureEncodingWithSigHashType(const valtype &vchSig,
                                                  uint32_t flags) {
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(CheckDataSignatureEncoding(vchSig, flags, &err));

    const bool hasStrictEnc = (flags & SCRIPT_VERIFY_STRICTENC) != 0;

    std::vector<BaseSigHashType> allBaseTypes{
        BaseSigHashType::ALL, BaseSigHashType::NONE, BaseSigHashType::SINGLE};

    std::vector<SigHashType> baseSigHashes;
    for (const BaseSigHashType baseType : allBaseTypes) {
        const SigHashType baseSigHash = SigHashType().withBaseType(baseType);
        baseSigHashes.push_back(baseSigHash);
        baseSigHashes.push_back(baseSigHash.withAnyoneCanPay(true));
    }

    for (const SigHashType baseSigHash : baseSigHashes) {
        // If we have strict encoding, we prevent the use of undefined flags.
        std::array<SigHashType, 2> undefSigHashes{
            SigHashType(baseSigHash.getRawSigHashType() | 0x20),
            baseSigHash.withBaseType(BaseSigHashType::UNSUPPORTED),
        };

        for (SigHashType undefSigHash : undefSigHashes) {
            valtype undefSighash = SignatureWithHashType(vchSig, undefSigHash);
            BOOST_CHECK_EQUAL(
                CheckTransactionSignatureEncoding(undefSighash, flags, &err),
                !hasStrictEnc);
            if (hasStrictEnc) {
                BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_HASHTYPE);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(checksignatureencoding_test) {
    valtype minimalSig{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    valtype highSSig{
        0x30, 0x45, 0x02, 0x20, 0x3e, 0x45, 0x16, 0xda, 0x72, 0x53, 0xcf, 0x06,
        0x8e, 0xff, 0xec, 0x6b, 0x95, 0xc4, 0x12, 0x21, 0xc0, 0xcf, 0x3a, 0x8e,
        0x6c, 0xcb, 0x8c, 0xbf, 0x17, 0x25, 0xb5, 0x62, 0xe9, 0xaf, 0xde, 0x2c,
        0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d, 0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45,
        0xa2, 0x0e, 0x0b, 0x99, 0x9e, 0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5,
        0x48, 0x0d, 0x48, 0x5f, 0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0};
    std::vector<valtype> nonDERSigs{
        // Non canonical total length.
        {0x30, 0x80, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        // Zero length R.
        {0x30, 0x2f, 0x02, 0x00, 0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d,
         0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99,
         0x9e, 0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d,
         0x48, 0x5f, 0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0},
        // Non canonical length for R.
        {0x30, 0x31, 0x02, 0x80, 0x01, 0x6c, 0x02, 0x21, 0x00, 0xab, 0x1e,
         0x3d, 0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99,
         0x9e, 0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48,
         0x5f, 0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0},
        // Negative R.
        {0x30, 0x30, 0x02, 0x01, 0x80, 0x02, 0x21, 0x00, 0xab, 0x1e,
         0x3d, 0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b,
         0x99, 0x9e, 0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48,
         0x0d, 0x48, 0x5f, 0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0},
        // Null prefixed R.
        {0x30, 0x31, 0x02, 0x02, 0x00, 0x01, 0x02, 0x21, 0x00, 0xab, 0x1e,
         0x3d, 0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99,
         0x9e, 0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48,
         0x5f, 0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0},
        // Zero length S.
        {0x30, 0x2f, 0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d, 0xa7, 0x3d,
         0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99, 0x9e, 0x04,
         0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48, 0x5f,
         0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0, 0x02, 0x00},
        // Non canonical length for S.
        {0x30, 0x31, 0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d, 0xa7, 0x3d, 0x67,
         0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99, 0x9e, 0x04, 0x99, 0x78,
         0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48, 0x5f, 0xcf, 0x2c, 0xe0,
         0xd0, 0x3b, 0x2e, 0xf0, 0x02, 0x80, 0x01, 0x6c},
        // Negative S.
        {0x30, 0x30, 0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d, 0xa7, 0x3d,
         0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99, 0x9e, 0x04,
         0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48, 0x5f,
         0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0, 0x02, 0x01, 0x80},
        // Null prefixed S.
        {0x30, 0x31, 0x02, 0x21, 0x00, 0xab, 0x1e, 0x3d, 0xa7, 0x3d, 0x67,
         0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99, 0x9e, 0x04, 0x99, 0x78,
         0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48, 0x5f, 0xcf, 0x2c, 0xe0,
         0xd0, 0x3b, 0x2e, 0xf0, 0x02, 0x02, 0x00, 0x01},
    };
    std::vector<valtype> nonParsableSigs{
        // Too short.
        {0x30},
        {0x30, 0x06},
        {0x30, 0x06, 0x02},
        {0x30, 0x06, 0x02, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01},
        // Invalid type (must be 0x30, coumpound).
        {0x42, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        // Invalid sizes.
        {0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        // Invalid R and S sizes.
        {0x30, 0x06, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x02, 0x01, 0x02, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01},
        // Invalid R and S types.
        {0x30, 0x06, 0x42, 0x01, 0x01, 0x02, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x01},
        // S out of bounds.
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00},
        // Too long.
        {0x30, 0x47, 0x02, 0x21, 0x00, 0x8e, 0x45, 0x16, 0xda, 0x72, 0x53,
         0xcf, 0x06, 0x8e, 0xff, 0xec, 0x6b, 0x95, 0xc4, 0x12, 0x21, 0xc0,
         0xcf, 0x3a, 0x8e, 0x6c, 0xcb, 0x8c, 0xbf, 0x17, 0x25, 0xb5, 0x62,
         0xe9, 0xaf, 0xde, 0x2c, 0x02, 0x22, 0x00, 0xab, 0x1e, 0x3d, 0x00,
         0xa7, 0x3d, 0x67, 0xe3, 0x20, 0x45, 0xa2, 0x0e, 0x0b, 0x99, 0x9e,
         0x04, 0x99, 0x78, 0xea, 0x8d, 0x6e, 0xe5, 0x48, 0x0d, 0x48, 0x5f,
         0xcf, 0x2c, 0xe0, 0xd0, 0x3b, 0x2e, 0xf0},
    };

    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t flags = 0; flags < (1U << 17); flags++) {
        ScriptError err = SCRIPT_ERR_OK;

        // Empty sig is always valid.
        BOOST_CHECK(CheckDataSignatureEncoding({}, flags, &err));
        BOOST_CHECK(CheckTransactionSignatureEncoding({}, flags, &err));

        // Signature are valid as long as the forkid flag is correct.
        CheckSignatureEncodingWithSigHashType(minimalSig, flags);

        if (flags & SCRIPT_VERIFY_LOW_S) {
            // If we do enforce low S, then high S sigs are rejected.
            BOOST_CHECK(!CheckDataSignatureEncoding(highSSig, flags, &err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_HIGH_S);
        } else {
            // If we do not enforce low S, then high S sigs are accepted.
            CheckSignatureEncodingWithSigHashType(highSSig, flags);
        }

        for (const valtype &nonDERSig : nonDERSigs) {
            if (flags & (SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) {
                // If we get any of the dersig flags, the non canonical dersig
                // signature fails.
                BOOST_CHECK(
                    !CheckDataSignatureEncoding(nonDERSig, flags, &err));
                BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);
            } else {
                // If we do not check, then it is accepted.
                BOOST_CHECK(CheckDataSignatureEncoding(nonDERSig, flags, &err));
            }
        }

        for (const valtype &nonDERSig : nonParsableSigs) {
            if (flags & (SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) {
                // If we get any of the dersig flags, the high S but non dersig
                // signature fails.
                BOOST_CHECK(
                    !CheckDataSignatureEncoding(nonDERSig, flags, &err));
                BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);
            } else {
                // If we do not check, then it is accepted.
                BOOST_CHECK(CheckDataSignatureEncoding(nonDERSig, flags, &err));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(checkpubkeyencoding_test) {
    valtype compressedKey0{0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                           0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
                           0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
                           0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    valtype compressedKey1{0x03, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
                           0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
                           0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
                           0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff};
    valtype fullKey{0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
                    0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
                    0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
                    0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
                    0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0, 0x0f, 0xff};

    std::vector<valtype> invalidKeys{
        // Degenerate keys.
        {},
        {0x00},
        {0x01},
        {0x02},
        {0x03},
        {0x04},
        {0x05},
        {0x42},
        {0xff},
        // Invalid first byte 0x00.
        {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Invalid first byte 0x01.
        {0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Invalid first byte 0x05.
        {0x05, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0x05, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Invalid first byte 0xff.
        {0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Compressed key too short.
        {0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0x03, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
         0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
         0xf0, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Compressed key too long.
        {0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
         0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0xab, 0xba, 0x9a,
         0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
        {0x03, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xab,
         0xba, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Compressed key, full key size.
        {0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        {0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Full key, too short.
        {0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
         0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Full key, too long.
        {0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
         0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
         0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
         0x56, 0x78, 0xab, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
         0x9a, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xde,
         0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xff},
        // Full key, compressed key size.
        {0x04, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
         0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0xab, 0xba, 0x9a,
         0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
    };

    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t flags = 0; flags < (1U << 17); flags++) {
        ScriptError err = SCRIPT_ERR_OK;

        // Compressed pubkeys are always valid.
        BOOST_CHECK(CheckPubKeyEncoding(compressedKey0, flags, &err));
        BOOST_CHECK(CheckPubKeyEncoding(compressedKey1, flags, &err));

        // If SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE is specified, full key are
        // disabled.
        const bool allowFullKey = true;
        BOOST_CHECK_EQUAL(CheckPubKeyEncoding(fullKey, flags, &err),
                          allowFullKey);

        // If SCRIPT_VERIFY_STRICTENC or SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE is
        // specified, we rule out invalid keys.
        const bool hasStrictEnc = (flags & SCRIPT_VERIFY_STRICTENC) != 0;
        const bool allowInvalidKeys = allowFullKey && !hasStrictEnc;
        for (const valtype &key : invalidKeys) {
            BOOST_CHECK_EQUAL(CheckPubKeyEncoding(key, flags, &err),
                              allowInvalidKeys);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
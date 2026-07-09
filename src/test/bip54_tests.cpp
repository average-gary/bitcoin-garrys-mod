// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <core_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <test/data/bip54_sigops.json.h>
#include <test/data/bip54_txsize.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(bip54_tests, BasicTestingSetup)

// BIP 54 §Specification rule 3: transactions whose witness-stripped serialized
// size is exactly 64 bytes are invalid. This is a per-transaction test — no
// UTXO, no block, no script execution needed.
BOOST_AUTO_TEST_CASE(bip54_txsize_json)
{
    const UniValue tests = read_json(std::string(json_tests::bip54_txsize));
    BOOST_REQUIRE(tests.isArray());

    for (unsigned int idx = 0; idx < tests.size(); ++idx) {
        const UniValue& t = tests[idx];
        BOOST_REQUIRE(t.isObject());
        const std::string comment = t["comment"].get_str();
        const std::string tx_hex = t["tx"].get_str();
        const bool expected_valid = t["valid"].get_bool();

        CMutableTransaction tx;
        BOOST_CHECK_MESSAGE(DecodeHexTx(tx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true),
                            "Bad test #" << idx << " (" << comment << "): could not decode tx hex");

        const size_t stripped_size = ::GetSerializeSize(TX_NO_WITNESS(CTransaction(tx)));
        const bool bip54_ok = stripped_size != 64;
        BOOST_CHECK_MESSAGE(bip54_ok == expected_valid,
                            "BIP 54 txsize mismatch #" << idx << " (" << comment
                            << "): stripped=" << stripped_size
                            << " expected_valid=" << expected_valid);
    }
}

// BIP 54 §Specification rule 2: sum of legacy sigops in each input's scriptSig
// plus the spent scriptPubKey (with P2SH accounting) must not exceed
// MAX_TX_LEGACY_SIGOPS (2500). Test vectors provide the tx along with a
// serialized CTxOut for each input; we mock a CCoinsView so CheckSigopsBIP54
// can look up each spent scriptPubKey.
BOOST_AUTO_TEST_CASE(bip54_sigops_json)
{
    const UniValue tests = read_json(std::string(json_tests::bip54_sigops));
    BOOST_REQUIRE(tests.isArray());

    for (unsigned int idx = 0; idx < tests.size(); ++idx) {
        const UniValue& t = tests[idx];
        BOOST_REQUIRE(t.isObject());
        const std::string comment = t["comment"].get_str();
        const std::string tx_hex = t["tx"].get_str();
        const bool expected_valid = t["valid"].get_bool();
        const UniValue& spent = t["spent_outputs"].get_array();

        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
            BOOST_ERROR("Bad test #" << idx << " (" << comment << "): could not decode tx hex");
            continue;
        }
        const CTransaction tx{mtx};

        // Each spent_outputs entry is a plain CTxOut serialization:
        //   [8-byte LE amount][CompactSize scriptPubKey length][scriptPubKey bytes]
        // Populate a mocked CCoinsView with these outputs so
        // CheckSigopsBIP54 can look up input.prevout -> scriptPubKey.
        BOOST_REQUIRE_EQUAL(spent.size(), tx.vin.size());

        CCoinsView dummy;
        CCoinsViewCache view{&dummy};
        for (unsigned int i = 0; i < tx.vin.size(); ++i) {
            const std::string sp_hex = spent[i].get_str();
            DataStream ss{ParseHex(sp_hex)};
            CTxOut txout;
            try {
                ss >> txout;
            } catch (const std::exception& e) {
                BOOST_ERROR("Bad test #" << idx << " (" << comment
                            << ") input " << i << ": " << e.what());
                continue;
            }
            Coin coin{std::move(txout), /*nHeightIn=*/1, /*fCoinBaseIn=*/false};
            view.AddCoin(tx.vin[i].prevout, std::move(coin), /*possible_overwrite=*/false);
        }

        const bool bip54_ok = CheckSigopsBIP54(tx, view);
        BOOST_CHECK_MESSAGE(bip54_ok == expected_valid,
                            "BIP 54 sigops mismatch #" << idx << " (" << comment
                            << "): expected_valid=" << expected_valid
                            << " got=" << bip54_ok);
    }
}

BOOST_AUTO_TEST_SUITE_END()

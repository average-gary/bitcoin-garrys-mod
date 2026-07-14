// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <node/context.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <validationinterface.h>
#include <test/data/bip54_sigops.json.h>
#include <test/data/bip54_txsize.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <validation.h>

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

// Block-level BIP 54 rules (coinbase locktime/sequence and the 64-byte tx ban)
// need a chain with BIP 54 active. Regtest activates DEPLOYMENT_BIP54 from
// height 0, so TestChain100Setup is the right fixture. The coinbases.json and
// timestamps.json reference vectors are chains descended from the *mainnet*
// genesis, which our unit-test harness can't easily replay; instead we exercise
// the same consensus rules behaviourally against hand-built regtest blocks.
BOOST_FIXTURE_TEST_SUITE(bip54_block_tests, TestChain100Setup)

namespace {
//! Captures the reject reason reported by BlockChecked for the most recently
//! validated block, so tests can assert the *specific* BIP 54 rejection.
struct RejectReasonSubscriber final : public CValidationInterface {
    std::string m_reason;
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState& state) override
    {
        m_reason = state.GetRejectReason();
    }
};

//! Re-solve a block's proof of work after mutating it.
void ResolvePoW(CBlock& block, const Consensus::Params& params)
{
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, params)) ++block.nNonce;
}

//! Submit a block and return the reject reason ("" if it connected).
std::string SubmitBlockReason(node::NodeContext& node, const CBlock& block)
{
    auto sub{std::make_shared<RejectReasonSubscriber>()};
    node.validation_signals->RegisterSharedValidationInterface(sub);
    const auto block_ptr{std::make_shared<const CBlock>(block)};
    bool new_block{false};
    Assert(node.chainman)->ProcessNewBlock(block_ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    node.validation_signals->UnregisterSharedValidationInterface(sub);
    return sub->m_reason;
}
} // namespace

// BIP 54 rule 4: coinbase nLockTime must equal height-1 and its input nSequence
// must not be 0xffffffff. A block assembled by BlockAssembler already satisfies
// this; mutating the coinbase must cause the specific rejection. These checks
// live in ContextualCheckBlock, which runs before input script verification, so
// an anyone-can-spend coinbase-only block is enough to reach them.
BOOST_AUTO_TEST_CASE(bip54_coinbase_locktime_sequence)
{
    const CScript spk{CScript() << OP_TRUE};
    const Consensus::Params& params{m_node.chainman->GetConsensus()};

    // Sanity: an unmutated assembled block connects (coinbase compliant).
    {
        CBlock good{CreateBlock({}, spk, m_node.chainman->ActiveChainstate())};
        BOOST_CHECK_EQUAL(SubmitBlockReason(m_node, good), "");
    }

    const int tip_height{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    const uint32_t next_height{static_cast<uint32_t>(tip_height + 1)};

    // Wrong coinbase nLockTime → bad-cb-locktime. Use a value that is still
    // "final" (a height below the current one) so IsFinalTx does not fire first
    // with bad-txns-nonfinal; it must simply differ from next_height - 1.
    {
        CBlock bad{CreateBlock({}, spk, m_node.chainman->ActiveChainstate())};
        CMutableTransaction cb{*bad.vtx[0]};
        BOOST_REQUIRE(next_height - 1 != 1u);
        cb.nLockTime = 1; // final (1 < next_height) but not next_height - 1
        bad.vtx[0] = MakeTransactionRef(std::move(cb));
        ResolvePoW(bad, params);
        BOOST_CHECK_EQUAL(SubmitBlockReason(m_node, bad), "bad-cb-locktime");
    }

    // Final coinbase nSequence (0xffffffff) → bad-cb-sequence.
    {
        CBlock bad{CreateBlock({}, spk, m_node.chainman->ActiveChainstate())};
        CMutableTransaction cb{*bad.vtx[0]};
        cb.vin[0].nSequence = 0xffffffff;
        bad.vtx[0] = MakeTransactionRef(std::move(cb));
        ResolvePoW(bad, params);
        BOOST_CHECK_EQUAL(SubmitBlockReason(m_node, bad), "bad-cb-sequence");
    }

    // A correctly-formed successor still connects afterwards.
    {
        CBlock good{CreateBlock({}, spk, m_node.chainman->ActiveChainstate())};
        BOOST_CHECK_EQUAL(SubmitBlockReason(m_node, good), "");
    }
}

// BIP 54 rule 3: a transaction whose witness-stripped serialized size is exactly
// 64 bytes is invalid. Splice such a transaction into an assembled block's vtx
// (leaving its scriptSig empty). The 64-byte check in ContextualCheckBlock runs
// before input script verification, so the block is rejected for txsize rather
// than for the missing signature.
BOOST_AUTO_TEST_CASE(bip54_block_rejects_64_byte_tx)
{
    const CScript spk{CScript() << OP_TRUE};
    const Consensus::Params& params{m_node.chainman->GetConsensus()};

    auto make_block_with_extra_tx = [&](const CMutableTransaction& extra) {
        CBlock block{CreateBlock({}, spk, m_node.chainman->ActiveChainstate())};
        block.vtx.push_back(MakeTransactionRef(extra));
        ResolvePoW(block, params);
        return block;
    };

    // A 64-byte (witness-stripped) transaction: OP_RETURN + three OP_0 opcodes.
    CMutableTransaction tx64;
    tx64.version = 2;
    tx64.vin.emplace_back(COutPoint{m_coinbase_txns[0]->GetHash(), 0}, CScript{});
    tx64.vout.emplace_back(CAmount{0}, CScript() << OP_RETURN << OP_0 << OP_0 << OP_0);
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(TX_NO_WITNESS(CTransaction{tx64})), 64U);

    CBlock bad{make_block_with_extra_tx(tx64)};
    BOOST_CHECK_EQUAL(SubmitBlockReason(m_node, bad), "bad-txns-txsize-64");

    // One byte larger (65 stripped bytes): it clears rule 3 and is instead
    // rejected downstream for the missing signature — proving it is specifically
    // the 64-byte size that trips bad-txns-txsize-64.
    CMutableTransaction tx65{tx64};
    tx65.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_0 << OP_0 << OP_0 << OP_0;
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(TX_NO_WITNESS(CTransaction{tx65})), 65U);

    CBlock other{make_block_with_extra_tx(tx65)};
    BOOST_CHECK_NE(SubmitBlockReason(m_node, other), "bad-txns-txsize-64");
}

BOOST_AUTO_TEST_SUITE_END()

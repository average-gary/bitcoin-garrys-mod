// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <memory>

using node::BlockAssembler;

namespace {

// Build a header-valid block on top of `prev_hash` with timestamp `nTime`.
// Reuses an assembler-produced template (so coinbase, witness commitment and
// merkle are well-formed), then overwrites prev/time so the caller can probe
// the timestamp rule.
std::shared_ptr<CBlock> BuildBlock(node::NodeContext& node, const uint256& prev_hash, int64_t nTime)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << OP_TRUE;
    options.include_dummy_extranonce = true;
    auto ptemplate = BlockAssembler{node.chainman->ActiveChainstate(), node.mempool.get(), options}.CreateNewBlock();
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = nTime;

    const int prev_height{WITH_LOCK(::cs_main, return node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight)};
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = CScript{} << prev_height + 1 << OP_0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    const CBlockIndex* prev_index{WITH_LOCK(::cs_main, return node.chainman->m_blockman.LookupBlockIndex(prev_hash))};
    node.chainman->GenerateCoinbaseCommitment(*pblock, prev_index);
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }
    return pblock;
}

void MineChain(node::NodeContext& node, int count, int64_t start_time)
{
    for (int i = 0; i < count; ++i) {
        const uint256 tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip()->GetBlockHash())};
        auto pblock = BuildBlock(node, tip, start_time + i);
        BlockValidationState state;
        BOOST_REQUIRE(Assert(node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
        bool new_block{false};
        BOOST_REQUIRE(Assert(node.chainman)->ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    }
}

int64_t TipTime(node::NodeContext& node)
{
    return WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip()->GetBlockTime());
}

int TipHeight(node::NodeContext& node)
{
    return WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Height());
}

uint256 TipHash(node::NodeContext& node)
{
    return WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip()->GetBlockHash());
}

struct MinDifficultyFixSetup : public TestingSetup {
    MinDifficultyFixSetup() : TestingSetup{ChainType::REGTEST, {.extra_args = {"-test=mindifffix"}}} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_min_difficulty_fix_tests, MinDifficultyFixSetup)

BOOST_AUTO_TEST_CASE(pre_fork_block_with_large_gap_accepted)
{
    // The fix activates at height 200. Mine to height 198 so the next block is
    // 199 (still pre-fork) and submit a header with a >1200s gap.
    MineChain(m_node, 198, /*start_time=*/Params().GenesisBlock().nTime + 1);
    BOOST_REQUIRE_EQUAL(TipHeight(m_node), 198);

    auto pblock = BuildBlock(m_node, TipHash(m_node), TipTime(m_node) + 1500);
    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
}

BOOST_AUTO_TEST_CASE(post_fork_overcap_block_rejected)
{
    // Mine to height 200 (the activation height itself, which is non-adjustment
    // since 200 % 144 != 0). Next block at height 201 must be rejected when
    // its timestamp is more than 1200s past the previous block.
    MineChain(m_node, 200, /*start_time=*/Params().GenesisBlock().nTime + 1);
    BOOST_REQUIRE_EQUAL(TipHeight(m_node), 200);

    const int64_t cap{TipTime(m_node) + Params().GetConsensus().nPowTargetSpacing * 2};
    auto pblock = BuildBlock(m_node, TipHash(m_node), cap + 1);
    BlockValidationState state;
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "time-too-far-ahead");
}

BOOST_AUTO_TEST_CASE(post_fork_at_cap_block_accepted)
{
    // Boundary: a block whose timestamp is exactly `prev + 2*nPowTargetSpacing`
    // is *not* over the cap (the rule uses a strict `>`).
    MineChain(m_node, 200, /*start_time=*/Params().GenesisBlock().nTime + 1);
    BOOST_REQUIRE_EQUAL(TipHeight(m_node), 200);

    const int64_t cap{TipTime(m_node) + Params().GetConsensus().nPowTargetSpacing * 2};
    auto pblock = BuildBlock(m_node, TipHash(m_node), cap);
    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
}

BOOST_AUTO_TEST_CASE(post_fork_adjustment_block_overcap_accepted)
{
    // Difficulty-adjustment blocks (heights divisible by
    // DifficultyAdjustmentInterval() = 144 on regtest) are exempt from the
    // cap. Mine to height 287 so the next block is 288 = 2 * 144, an
    // adjustment block. A >1200s gap there must still be accepted.
    MineChain(m_node, 287, /*start_time=*/Params().GenesisBlock().nTime + 1);
    BOOST_REQUIRE_EQUAL(TipHeight(m_node), 287);
    BOOST_REQUIRE_EQUAL((TipHeight(m_node) + 1) % Params().GetConsensus().DifficultyAdjustmentInterval(), 0);

    auto pblock = BuildBlock(m_node, TipHash(m_node), TipTime(m_node) + Params().GetConsensus().nPowTargetSpacing * 2 + 1);
    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(validation_min_difficulty_fix_disabled_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(rule_disabled_when_param_zero)
{
    // Without -test=mindifffix the rule is inactive
    // (min_difficulty_blocks_fix_height = 0), so an over-cap block at the
    // same height is accepted on default regtest.
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().min_difficulty_blocks_fix_height, 0);

    MineChain(m_node, 200, /*start_time=*/Params().GenesisBlock().nTime + 1);
    BOOST_REQUIRE_EQUAL(TipHeight(m_node), 200);

    auto pblock = BuildBlock(m_node, TipHash(m_node),
                             TipTime(m_node) + Params().GetConsensus().nPowTargetSpacing * 2 + 1);
    BlockValidationState state;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{*pblock}}, true, state));
}

BOOST_AUTO_TEST_SUITE_END()

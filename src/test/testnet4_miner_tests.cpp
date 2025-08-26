// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;
using node::BlockWaitOptions;

namespace testnet4_miner_tests {

struct Testnet4MinerTestingSetup : public Testnet4Setup {
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node);
    }
};
} // namespace testnet4_miner_tests

BOOST_FIXTURE_TEST_SUITE(testnet4_miner_tests, Testnet4MinerTestingSetup)

BOOST_AUTO_TEST_CASE(MiningInterface)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    std::unique_ptr<BlockTemplate> block_template;

    // Set node time a few minutes past the testnet4 genesis block
    const int64_t genesis_time{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockTime())};
    SetMockTime(genesis_time + 3 * 60);

    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);

    // The template should use the mocked system time
    BOOST_REQUIRE_EQUAL(block_template->getBlockHeader().nTime, genesis_time + 3 * 60);

    const BlockWaitOptions wait_options{.timeout = MillisecondsDouble{0}, .fee_threshold = 1};

    // waitNext() should return nullptr because there is no better template
    auto should_be_nullptr = block_template->waitNext(wait_options);
    BOOST_REQUIRE(should_be_nullptr == nullptr);

    // This remains the case when exactly 20 minutes have gone by
    {
        LOCK(cs_main);
        SetMockTime(m_node.chainman->ActiveChain().Tip()->GetBlockTime() + 20 * 60);
    }
    should_be_nullptr = block_template->waitNext(wait_options);
    BOOST_REQUIRE(should_be_nullptr == nullptr);

    // One second later the difficulty drops and it returns a new template
    // Note that we can't test the actual difficulty change, because the
    // difficulty is already at 1.
    {
        LOCK(cs_main);
        SetMockTime(m_node.chainman->ActiveChain().Tip()->GetBlockTime() + 20 * 60 + 1);
    }
    block_template = block_template->waitNext(wait_options);
    BOOST_REQUIRE(block_template);
}

BOOST_AUTO_TEST_CASE(MinimumDifficultyDetection)
{
    // Test minimum difficulty block detection
    const auto& params = Params().GetConsensus();
    
    // Create a mock block index with minimum difficulty
    CBlockIndex min_diff_block{};
    const uint32_t powLimitBits = UintToArith256(params.powLimit).GetCompact();
    min_diff_block.nBits = powLimitBits;
    
    // Create a mock block index with normal difficulty (higher difficulty = lower target)
    CBlockIndex normal_block{};
    normal_block.nBits = powLimitBits - 1; // This is higher difficulty
    
    // Debug output
    BOOST_TEST_MESSAGE("powLimit compact: " << std::hex << powLimitBits);
    BOOST_TEST_MESSAGE("min_diff_block.nBits: " << std::hex << min_diff_block.nBits);
    BOOST_TEST_MESSAGE("normal_block.nBits: " << std::hex << normal_block.nBits);
    
    BOOST_CHECK(node::IsMinimumDifficultyBlock(&min_diff_block, params));
    BOOST_CHECK(!node::IsMinimumDifficultyBlock(&normal_block, params));
    BOOST_CHECK(!node::IsMinimumDifficultyBlock(nullptr, params));
}

BOOST_AUTO_TEST_CASE(FindBestNonMinDiffAncestor)
{
    const auto& params = Params().GetConsensus();
    
    // Create a chain: normal -> min_diff1 -> min_diff2 -> min_diff3 (tip)
    CBlockIndex normal_block{}, min_diff1{}, min_diff2{}, min_diff3{};
    
    const uint32_t powLimitBits = UintToArith256(params.powLimit).GetCompact();
    normal_block.nBits = powLimitBits - 1; // Higher difficulty (not minimum)
    min_diff1.nBits = powLimitBits; // Min difficulty
    min_diff2.nBits = powLimitBits; // Min difficulty  
    min_diff3.nBits = powLimitBits; // Min difficulty
    
    // Link the chain
    normal_block.pprev = nullptr;
    min_diff1.pprev = &normal_block;
    min_diff2.pprev = &min_diff1;
    min_diff3.pprev = &min_diff2;
    
    // Should find the normal block as the best ancestor
    const CBlockIndex* best = node::FindBestNonMinDiffAncestor(&min_diff3, params, 10);
    BOOST_CHECK_EQUAL(best, &normal_block);
    
    // Should return the same block if it's not minimum difficulty
    best = node::FindBestNonMinDiffAncestor(&normal_block, params, 10);
    BOOST_CHECK_EQUAL(best, &normal_block);
    
    // Should respect max_depth limit - start from min_diff3, go back 2 steps to reach min_diff1
    best = node::FindBestNonMinDiffAncestor(&min_diff3, params, 2);
    BOOST_CHECK_EQUAL(best, &min_diff1); // Should stop at depth 2 and return the last checked
}

BOOST_AUTO_TEST_CASE(Testnet4AntiSpamReorg)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    
    // Enable testnet4 anti-spam feature
    options.testnet4_antispam_reorg = true;
    options.testnet4_max_reorg_depth = 5;
    
    // Test with feature enabled
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    
    // Test with feature disabled
    options.testnet4_antispam_reorg = false;
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    
    // Test with different max reorg depth
    options.testnet4_antispam_reorg = true;
    options.testnet4_max_reorg_depth = 1;
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
}

BOOST_AUTO_TEST_SUITE_END()

#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the min-difficulty block exploit soft-fork rule.

Once active, a non-adjustment block whose timestamp exceeds the previous
block's timestamp by more than 2 * nPowTargetSpacing (1200 s on regtest with
600 s spacing) must be rejected with reject reason "time-too-far-ahead".
Difficulty-adjustment blocks (heights divisible by 144 on regtest) are
exempt. The miner-side timestamp clamp in BlockAssembler/UpdateTime is also
covered via getblocktemplate's `curtime`.

Activation height on regtest is 200 when -test=mindifffix is set.
"""

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_coinbase,
)
from test_framework.messages import (
    CBlock,
    CBlockHeader,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


ACTIVATION_HEIGHT = 200
REGTEST_TARGET_SPACING = 600
CAP_GAP = 2 * REGTEST_TARGET_SPACING  # 1200 seconds
DIFFICULTY_ADJUSTMENT_INTERVAL = 144


def build_block(node, prev_hash, n_time, height):
    """Build a PoW-solved block at `height` on top of `prev_hash`."""
    tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
    block = CBlock()
    block.nVersion = tmpl["version"]
    block.hashPrevBlock = int(prev_hash, 16)
    block.nTime = n_time
    block.nBits = int(tmpl["bits"], 16)
    block.nNonce = 0
    block.vtx = [create_coinbase(height=height)]
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block


class MinDifficultyFixTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=mindifffix"]]

    def mine_to_height(self, target):
        """Mine blocks with 1-second timestamp gaps to reach `target`."""
        t = self.nodes[0].getblock(self.nodes[0].getbestblockhash())["time"]
        while self.nodes[0].getblockcount() < target:
            t += 1
            self.nodes[0].setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), target)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        # Mine to height 199 (one block below activation).
        t = node.getblockchaininfo()["time"]
        for _ in range(199):
            t += 1
            node.setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 199)

        prev_hash = node.getbestblockhash()
        prev_time = node.getblock(prev_hash)["time"]

        # Activation height is 200 (>= 200) and 200 % 144 == 56, so the rule
        # IS active at height 200 itself.
        self.log.info("Reject case at activation height: gap of 1201s at height 200 must fail with 'time-too-far-ahead'.")
        bad_at_200 = build_block(node, prev_hash, prev_time + CAP_GAP + 1, 200)
        assert_raises_rpc_error(-25, "time-too-far-ahead",
            lambda: node.submitheader(hexdata=CBlockHeader(bad_at_200).serialize().hex()))

        self.log.info("Boundary at activation height: gap of exactly 1200s at height 200 is accepted.")
        ok_at_200 = build_block(node, prev_hash, prev_time + CAP_GAP, 200)
        node.submitheader(hexdata=CBlockHeader(ok_at_200).serialize().hex())
        # Submit the full block so the chain advances to 200.
        node.submitblock(ok_at_200.serialize().hex())
        assert_equal(node.getblockcount(), 200)

        prev_hash = node.getbestblockhash()
        prev_time = node.getblock(prev_hash)["time"]

        self.log.info("Reject case post-activation: gap of 1201s at height 201 must fail.")
        bad = build_block(node, prev_hash, prev_time + CAP_GAP + 1, 201)
        assert_raises_rpc_error(-25, "time-too-far-ahead",
            lambda: node.submitheader(hexdata=CBlockHeader(bad).serialize().hex()))

        self.log.info("Boundary post-activation: gap of exactly 1200s at height 201 is accepted.")
        ok = build_block(node, prev_hash, prev_time + CAP_GAP, 201)
        node.submitheader(hexdata=CBlockHeader(ok).serialize().hex())
        node.submitblock(ok.serialize().hex())
        assert_equal(node.getblockcount(), 201)

        self.log.info("getblocktemplate's `curtime` is clamped once active.")
        tip_time = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(tip_time + 9999)
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_greater_than_or_equal(tip_time + CAP_GAP, tmpl["curtime"])

        self.log.info("Adjustment-block exemption: at height 288 (=2*144), a 1201s gap is accepted.")
        # Reset mocktime so subsequent self.generate calls produce blocks
        # with timestamps below the cap.
        self.mine_to_height(287)
        prev_hash = node.getbestblockhash()
        prev_time = node.getblock(prev_hash)["time"]
        adj_block = build_block(node, prev_hash, prev_time + CAP_GAP + 1, 288)
        node.submitheader(hexdata=CBlockHeader(adj_block).serialize().hex())


if __name__ == '__main__':
    MinDifficultyFixTest(__file__).main()

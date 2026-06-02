#include <sv2/messages.h>

#include <arith_uint256.h>
#include <node/mining_types.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

node::Sv2NewTemplateMsg::Sv2NewTemplateMsg(const CBlockHeader& header, const node::CoinbaseTx& coinbase_tx, std::vector<uint256> coinbase_merkle_path, uint64_t template_id, bool future_template)
    : m_template_id{template_id}, m_future_template{future_template}
{
    m_version = header.nVersion;

    m_coinbase_tx_version = coinbase_tx.version;
    m_coinbase_prefix = coinbase_tx.script_sig_prefix;
    m_coinbase_tx_input_sequence = coinbase_tx.sequence;

    // The coinbase value already contains the nFee + the Block Subsidy when built using CreateBlock().
    m_coinbase_tx_value_remaining = static_cast<uint64_t>(coinbase_tx.block_reward_remaining);

    m_coinbase_tx_outputs_count = static_cast<uint32_t>(coinbase_tx.required_outputs.size());
    m_coinbase_tx_outputs = coinbase_tx.required_outputs;

    m_coinbase_tx_locktime = coinbase_tx.lock_time;

    for (const auto& hash : coinbase_merkle_path) {
        m_merkle_path.push_back(hash);
    }
}

node::Sv2SetNewPrevHashMsg::Sv2SetNewPrevHashMsg(const CBlockHeader& header, uint64_t template_id) : m_template_id{template_id}
{
    m_prev_hash = header.hashPrevBlock;
    m_header_timestamp = header.nTime;
    m_nBits = header.nBits;
    m_target = ArithToUint256(arith_uint256().SetCompact(header.nBits));
}

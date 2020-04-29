from ex2 import *
import pytest  # type: ignore
import secrets
import hashlib
from typing import Callable, List, Any
from unittest.mock import Mock

EvilNodeMaker = Callable[[List[Block]], Mock]
KeyFactory = Callable[[], PublicKey]


def test_wallet_functionality_at_init(alice: Node) -> None:
    assert alice.get_address()
    assert alice.get_balance() == 0
    assert alice.create_transaction(alice.get_address()) is None


def test_node_functionality_at_init(alice: Node) -> None:
    assert alice.get_utxo() == []
    assert alice.get_latest_hash() == GENESIS_BLOCK_PREV
    assert alice.get_mempool() == []


def test_mine_single_block_and_generate_coin(alice: Node) -> None:
    block_hash = alice.mine_block()
    assert block_hash != GENESIS_BLOCK_PREV
    assert alice.get_latest_hash() == block_hash
    assert len(alice.get_utxo()) == 1
    assert alice.get_mempool() == []
    assert alice.get_balance() == 1

    block = alice.get_block(block_hash)
    assert block.get_block_hash() == block_hash
    assert block.get_prev_block_hash() == GENESIS_BLOCK_PREV
    transactions = block.get_transactions()
    assert transactions[0] == alice.get_utxo()[0]
    assert transactions[0].input is None
    assert transactions[0].output == alice.get_address()


def test_retreive_block_fails_on_junk_hash(alice: Node) -> None:
    with pytest.raises(ValueError):
        alice.get_block(GENESIS_BLOCK_PREV)
    bogus_hash = BlockHash(hashlib.sha256(b"no_such_block").digest())
    with pytest.raises(ValueError):
        alice.get_block(bogus_hash)
    h = alice.mine_block()
    with pytest.raises(ValueError):
        alice.get_block(bogus_hash)
    assert alice.get_block(h)


def test_transaction_creation(alice: Node, bob: Node, charlie: Node) -> None:
    alice.mine_block()
    assert alice.get_balance() == 1
    tx = alice.create_transaction(bob.get_address())
    assert tx is not None
    assert tx.input == alice.get_utxo()[0].get_txid()
    assert tx.output == bob.get_address()
    assert bob.get_balance() == 0
    assert charlie.get_balance() == 0


def test_node_updates_when_notified(alice: Node, evil_node_maker: EvilNodeMaker,
                                    make_key: KeyFactory) -> None:
    block1 = Block(GENESIS_BLOCK_PREV, [Transaction(make_key(), None, Signature(secrets.token_bytes(48)))])
    block_chain = [block1]
    eve = evil_node_maker(block_chain)
    alice.notify_of_block(eve.get_latest_hash(), eve)
    assert alice.get_latest_hash() != GENESIS_BLOCK_PREV


def test_node_updates_when_notified_two_blocks(alice: Node, evil_node_maker: EvilNodeMaker,
                                               make_key: KeyFactory) -> None:
    tx1 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    block1 = Block(GENESIS_BLOCK_PREV, [tx1])
    tx2 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    block2 = Block(block1.get_block_hash(), [tx2])

    block_chain = [block1, block2]
    eve = evil_node_maker(block_chain)
    alice.notify_of_block(eve.get_latest_hash(), eve)
    assert alice.get_latest_hash() == block2.get_block_hash()
    assert tx1 in alice.get_utxo()
    assert tx2 in alice.get_utxo()
    assert len(alice.get_utxo()) == 2
    assert alice.get_block(block1.get_block_hash()) == block1
    assert alice.get_block(block2.get_block_hash()) == block2


def test_node_does_not_update_when_alternate_chain_does_not_lead_to_genesis(alice: Node, evil_node_maker: EvilNodeMaker,
                                                                            make_key: KeyFactory) -> None:
    block1 = Block(BlockHash(hashlib.sha256(b"Not Genesis").digest()),
                   [Transaction(make_key(), None, Signature(secrets.token_bytes(48)))])
    block2 = Block(block1.get_block_hash(), [Transaction(make_key(), None, Signature(secrets.token_bytes(48)))])
    block3 = Block(block2.get_block_hash(), [Transaction(make_key(), None, Signature(secrets.token_bytes(48)))])

    evil_node = evil_node_maker([block1, block2, block3])

    alice.notify_of_block(block3.get_block_hash(), evil_node)
    assert alice.get_latest_hash() == GENESIS_BLOCK_PREV


def test_node_does_not_fully_update_when_some_transaction_is_bad(alice: Node, bob: Node, evil_node_maker: EvilNodeMaker,
                                                                 make_key: KeyFactory) -> None:
    bob.mine_block()
    tx0 = bob.create_transaction(alice.get_address())
    assert tx0 is not None

    tx1 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    block1 = Block(GENESIS_BLOCK_PREV, [tx1])
    tx2 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    tx3 = Transaction(make_key(), tx1.get_txid(), tx0.signature)  # the sig here is wrong!

    block2 = Block(block1.get_block_hash(), [tx2, tx3])
    mock_node = evil_node_maker([block1, block2])
    alice.notify_of_block(mock_node.get_latest_hash(), mock_node)
    assert alice.get_latest_hash() == block1.get_block_hash()


def test_node_does_not_update_when_creating_too_much_money(alice: Node, evil_node_maker: EvilNodeMaker,
                                                           make_key: KeyFactory) -> None:
    tx1 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    tx2 = Transaction(make_key(), None, Signature(secrets.token_bytes(48)))
    block = Block(GENESIS_BLOCK_PREV, [tx1, tx2])
    mock_node = evil_node_maker([block])
    alice.notify_of_block(mock_node.get_latest_hash(), mock_node)
    assert alice.get_latest_hash() == GENESIS_BLOCK_PREV
    assert alice.get_utxo() == []


def test_node_double_spends_when_mempool_clears(alice: Node, bob: Node) -> None:
    alice.mine_block()
    tx1 = alice.create_transaction(bob.get_address())
    assert tx1 is not None
    tx2 = alice.create_transaction(bob.get_address())
    assert tx2 is None
    alice.clear_mempool()
    assert alice.get_mempool() == []
    tx3 = alice.create_transaction(bob.get_address())
    assert tx3 is not None


def test_transactions_to_different_targets_are_different(alice: Node, bob: Node, charlie: Node) -> None:
    alice.mine_block()
    tx1 = alice.create_transaction(bob.get_address())
    alice.clear_mempool()
    tx2 = alice.create_transaction(charlie.get_address())
    assert tx1 is not None and tx2 is not None
    assert tx1.get_txid() != tx2.get_txid()


def test_transaction_rejected_if_we_change_output(alice: Node, bob: Node, charlie: Node) -> None:
    alice.mine_block()
    tx = alice.create_transaction(bob.get_address())
    assert tx is not None
    tx2 = Transaction(charlie.get_address(), tx.input, tx.signature)
    alice.clear_mempool()
    assert alice.add_transaction_to_mempool(tx)
    alice.clear_mempool()
    assert not alice.add_transaction_to_mempool(tx2)


def test_transaction_not_propagated_if_it_double_spends_a_mempool_tx(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    alice.mine_block()
    tx1 = alice.create_transaction(bob.get_address())
    assert tx1 is not None
    alice.clear_mempool()
    assert tx1 in bob.get_mempool()
    bob.connect(charlie)
    tx2 = alice.create_transaction(charlie.get_address())
    assert tx2 is not None
    assert tx2 in alice.get_mempool()
    assert tx2 not in bob.get_mempool()
    assert tx2 not in charlie.get_mempool()


def test_connections_exist(alice: Node, bob: Node, charlie: Node) -> None:
    assert alice.get_connections() == set()
    alice.connect(bob)
    assert bob in alice.get_connections()
    assert alice in bob.get_connections()

    bob.connect(charlie)
    bob.disconnect_from(alice)
    assert bob not in alice.get_connections()
    assert alice not in bob.get_connections()
    assert charlie in bob.get_connections()


def test_connect_to_self_fails(alice: Node) -> None:
    with pytest.raises(Exception):
        alice.connect(alice)


def test_connections_propagate_blocks(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    alice.mine_block()
    assert len(bob.get_utxo()) == 1
    assert alice.get_latest_hash() == bob.get_latest_hash()
    assert charlie.get_latest_hash() == GENESIS_BLOCK_PREV


def test_connections_propagate_txs(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    alice.mine_block()

    tx = alice.create_transaction(bob.get_address())
    assert tx in bob.get_mempool()
    assert tx not in charlie.get_mempool()


def test_block_hash(alice: Node, evil_node_maker: EvilNodeMaker, make_key: KeyFactory) -> None:
    block_hash1 = alice.mine_block()
    block1 = alice.get_block(block_hash1)
    assert block1.get_block_hash() == block_hash1

    transactions = block1.get_transactions()
    prev = block1.get_prev_block_hash()
    bogus_hash = BlockHash(hashlib.sha256(b"no_such_block").digest())
    block2 = Block(bogus_hash, transactions)
    block3 = Block(prev, transactions * 2)
    block4 = Block(prev, [])
    assert block2.get_block_hash() != block_hash1
    assert block3.get_block_hash() != block_hash1
    assert block4.get_block_hash() != block_hash1

    # Additions
    block5 = Block(block3.get_block_hash(), [])
    mock_node = evil_node_maker([block1, block3, block5])
    alice.notify_of_block(mock_node.get_latest_hash(), mock_node)

    assert block1 == alice.get_block(block1.get_block_hash())
    with pytest.raises(Exception):
        alice.get_block(block3.get_block_hash())
    with pytest.raises(Exception):
        alice.get_block(block5.get_block_hash())


def test_catching_up_after_disconnect(alice: Node, bob: Node) -> None:
    alice.connect(bob)
    alice.mine_block()
    alice.disconnect_from(bob)
    h2 = alice.mine_block()
    alice.connect(bob)
    assert bob.get_latest_hash() == h2


def test_longer_chain_overtake(alice: Node, bob: Node) -> None:
    h1 = alice.mine_block()
    h2 = alice.mine_block()
    bob.mine_block()
    alice.connect(bob)
    assert bob.get_latest_hash() == h2
    assert bob.get_block(h2).get_prev_block_hash() == h1
    assert bob.get_block(h1).get_prev_block_hash() == GENESIS_BLOCK_PREV
    assert set(bob.get_utxo()) == set(alice.get_utxo())


def test_tx_surives_in_mempool_if_not_included_in_block(alice: Node, bob: Node) -> None:
    alice.connect(bob)
    bob.mine_block()
    bob.create_transaction(alice.get_address())
    bob.disconnect_from(alice)

    alice.clear_mempool()
    block_hash = alice.mine_block()
    bob.connect(alice)
    assert bob.get_latest_hash() == block_hash
    assert len(bob.get_mempool()) == 1  # TODO it's also in alice's MemPool, is it OK? Why does it happen?


def test_tx_replaced_in_blockchain_when_double_spent(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    alice.connect(charlie)
    alice.mine_block()
    alice.disconnect_from(charlie)
    tx1 = alice.create_transaction(bob.get_address())
    alice.mine_block()
    alice.disconnect_from(bob)

    assert tx1 in bob.get_utxo()
    assert tx1 in alice.get_utxo()

    charlie.mine_block()
    charlie.mine_block()

    alice.connect(charlie)
    alice.clear_mempool()  # in case you restore transactions to mempool
    assert tx1 not in alice.get_utxo()
    assert tx1 not in alice.get_mempool()
    # Note that tx2 will not enter charlie's MemPool unless its will be cleared from tx1 (they use the same coin).
    tx2 = alice.create_transaction(charlie.get_address())
    assert tx2 is not None
    assert tx2 in alice.get_mempool()
    alice.mine_block()
    alice.mine_block()
    assert tx2 in alice.get_utxo()
    alice.connect(bob)
    assert tx2 in bob.get_utxo()
    assert tx1 not in bob.get_utxo()
    assert tx1 not in bob.get_mempool()


def test_bob_serves_wrong_block(alice: Node, bob: Node, charlie: Node, monkeypatch: Any) -> None:
    # we ask charlie to create a block
    h1 = charlie.mine_block()
    block = charlie.get_block(h1)

    h2 = bob.mine_block()

    # now we make bob respond to block requests with charlie's block
    monkeypatch.setattr(bob, "get_block", lambda block_hash: block)

    alice.connect(bob)
    assert alice.get_latest_hash() == GENESIS_BLOCK_PREV
    assert alice.get_utxo() == []


def test_alternative_chain_tx_double_spend_tx_in_the_removed_chain(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    bob.connect(charlie)

    block1_hash = alice.mine_block()
    tx1 = alice.create_transaction(bob.get_address())
    assert alice.get_mempool() == bob.get_mempool() == charlie.get_mempool() == [tx1]

    alice.clear_mempool()
    alice.disconnect_from(bob)

    assert alice.get_balance() == 1
    assert bob.get_balance() == 0
    assert charlie.get_balance() == 0
    assert len(alice.get_mempool()) == 0
    assert bob.get_mempool() == charlie.get_mempool() == [tx1]
    assert set(alice.get_utxo()) == set(bob.get_utxo()) == set(charlie.get_utxo())
    assert alice.get_latest_hash() == bob.get_latest_hash() == charlie.get_latest_hash() == block1_hash
    assert (alice.get_block(block1_hash).get_prev_block_hash() ==
            bob.get_block(block1_hash).get_prev_block_hash() ==
            charlie.get_block(block1_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)

    tx2 = alice.create_transaction(charlie.get_address())
    block2_hash = alice.mine_block()

    assert alice.get_balance() == 1
    assert bob.get_balance() == 0
    assert charlie.get_balance() == 0
    assert tx2 in alice.get_utxo() and len(alice.get_utxo()) == 2
    assert len(alice.get_mempool()) == 0
    assert bob.get_mempool() == charlie.get_mempool() == [tx1]
    assert set(bob.get_utxo()) == set(charlie.get_utxo())
    assert alice.get_latest_hash() == block2_hash
    assert alice.get_block(block2_hash).get_prev_block_hash() == block1_hash
    assert bob.get_latest_hash() == charlie.get_latest_hash() == block1_hash
    assert (alice.get_block(block1_hash).get_prev_block_hash() ==
            bob.get_block(block1_hash).get_prev_block_hash() ==
            charlie.get_block(block1_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)

    block3_hash = charlie.mine_block()
    block4_hash = charlie.mine_block()

    assert alice.get_balance() == 1  # alice is not aware of the update yet
    assert bob.get_balance() == 1
    assert charlie.get_balance() == 2
    assert tx2 in alice.get_utxo() and len(alice.get_utxo()) == 2
    assert tx1 in bob.get_utxo() and len(bob.get_utxo()) == 3
    assert len(alice.get_mempool()) == len(bob.get_mempool()) == len(charlie.get_mempool()) == 0
    assert set(bob.get_utxo()) == set(charlie.get_utxo())
    assert alice.get_latest_hash() == block2_hash
    assert alice.get_block(block2_hash).get_prev_block_hash() == block1_hash
    assert bob.get_latest_hash() == charlie.get_latest_hash() == block4_hash
    assert (bob.get_block(block4_hash).get_prev_block_hash() ==
            charlie.get_block(block4_hash).get_prev_block_hash() ==
            block3_hash)
    assert (bob.get_block(block3_hash).get_prev_block_hash() ==
            charlie.get_block(block3_hash).get_prev_block_hash() ==
            block1_hash)
    assert (alice.get_block(block1_hash).get_prev_block_hash() ==
            bob.get_block(block1_hash).get_prev_block_hash() ==
            charlie.get_block(block1_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)

    alice.connect(bob)

    assert alice.get_balance() == 0  # alice is now aware of the update
    assert bob.get_balance() == 1
    assert charlie.get_balance() == 2
    assert len(alice.get_mempool()) == len(bob.get_mempool()) == len(charlie.get_mempool()) == 0
    assert tx1 in bob.get_utxo() and len(bob.get_utxo()) == 3
    assert set(alice.get_utxo()) == set(bob.get_utxo()) == set(charlie.get_utxo())
    assert alice.get_latest_hash() == bob.get_latest_hash() == charlie.get_latest_hash() == block4_hash
    assert (alice.get_block(block4_hash).get_prev_block_hash() ==
            bob.get_block(block4_hash).get_prev_block_hash() ==
            charlie.get_block(block4_hash).get_prev_block_hash() ==
            block3_hash)
    assert (alice.get_block(block3_hash).get_prev_block_hash() ==
            bob.get_block(block3_hash).get_prev_block_hash() ==
            charlie.get_block(block3_hash).get_prev_block_hash() ==
            block1_hash)
    assert (alice.get_block(block1_hash).get_prev_block_hash() ==
            bob.get_block(block1_hash).get_prev_block_hash() ==
            charlie.get_block(block1_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)


def test_alternative_chain_later_tx_use_earlier_tx_in_that_chain(alice: Node, bob: Node, charlie: Node) -> None:
    bob.connect(charlie)
    block1_hash = alice.mine_block()
    block2_hash = bob.mine_block()
    bob.create_transaction(charlie.get_address())
    block3_hash = bob.mine_block()

    assert alice.get_balance() == 1
    assert bob.get_balance() == 1
    assert charlie.get_balance() == 1
    assert alice.get_latest_hash() == block1_hash
    assert alice.get_block(block1_hash).get_prev_block_hash() == GENESIS_BLOCK_PREV
    assert bob.get_latest_hash() == charlie.get_latest_hash() == block3_hash
    assert (bob.get_block(block3_hash).get_prev_block_hash() ==
            charlie.get_block(block3_hash).get_prev_block_hash() ==
            block2_hash)
    assert (bob.get_block(block2_hash).get_prev_block_hash() ==
            charlie.get_block(block2_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)

    charlie.connect(alice)

    assert alice.get_balance() == 0
    assert bob.get_balance() == 1
    assert charlie.get_balance() == 1
    assert alice.get_mempool() == bob.get_mempool() == charlie.get_mempool() == []
    assert set(alice.get_utxo()) == set(bob.get_utxo()) == set(charlie.get_utxo())
    assert alice.get_latest_hash() == bob.get_latest_hash() == charlie.get_latest_hash() == block3_hash
    assert (alice.get_block(block3_hash).get_prev_block_hash() ==
            bob.get_block(block3_hash).get_prev_block_hash() ==
            charlie.get_block(block3_hash).get_prev_block_hash() ==
            block2_hash)
    assert (alice.get_block(block2_hash).get_prev_block_hash() ==
            bob.get_block(block2_hash).get_prev_block_hash() ==
            charlie.get_block(block2_hash).get_prev_block_hash() ==
            GENESIS_BLOCK_PREV)


def test_same_tx_in_both_chains(alice: Node, bob: Node, charlie: Node) -> None:
    alice.connect(bob)
    block1_hash = alice.mine_block()
    assert alice.get_block(block1_hash)
    assert alice.get_balance() == 1
    assert len(alice.get_utxo()) == 1

    tx = alice.create_transaction(bob.get_address())
    assert alice.get_balance() == 1
    assert bob.get_balance() == 0
    assert tx in alice.get_mempool()
    assert tx in bob.get_mempool()

    tx_impossible = bob.create_transaction(alice.get_address())
    assert tx_impossible is None

    block2_hash = bob.mine_block()
    assert alice.get_balance() == 0
    assert bob.get_balance() == 2
    assert tx in bob.get_block(block2_hash).get_transactions()
    assert tx in bob.get_utxo()
    assert len(alice.get_mempool()) == 0
    assert len(bob.get_mempool()) == 0

    tx2_1 = bob.create_transaction(alice.get_address())
    tx2_2 = bob.create_transaction(alice.get_address())
    assert bob.create_transaction(alice.get_address()) is None
    assert bob.get_balance() == 2
    bob.clear_mempool()
    assert bob.get_balance() == 2

    assert (tx2_1 in alice.get_mempool()) and (tx2_2 in alice.get_mempool())
    assert len(bob.get_mempool()) == 0

    bob.disconnect_from(alice)
    bob.disconnect_from(alice)      # Nothing should happen
    bob.disconnect_from(charlie)    # Nothing should happen
    alice.disconnect_from(bob)      # Nothing should happen

    block3_hash = alice.mine_block()
    assert alice.get_balance() == 3
    assert bob.get_balance() == 2       # Bob does not know about the update yet
    assert len(alice.get_mempool()) == 0

    tx3 = bob.create_transaction(bob.get_address())
    assert [tx3] == bob.get_mempool()
    block4_hash = bob.mine_block()
    assert len(bob.get_mempool()) == 0
    block5_hash = bob.mine_block()
    assert alice.get_balance() == 3
    assert bob.get_balance() == 4

    assert alice.get_block(block3_hash)
    assert bob.get_block(block4_hash)
    assert bob.get_block(block5_hash)

    alice.connect(bob)

    with pytest.raises(ValueError):
        alice.get_block(block3_hash)
    with pytest.raises(ValueError):
        bob.get_block(block3_hash)

    assert alice.get_balance() == 0
    assert bob.get_balance() == 4
    assert (tx2_1 in alice.get_mempool()) != (tx2_2 in alice.get_mempool()), \
        "Exactly one of them should be in the MemPool, since we are restoring transactions that can still happen"

    block6_hash = alice.mine_block()

    assert alice.get_block(block6_hash)
    assert alice.get_balance() == 2
    assert bob.get_balance() == 3

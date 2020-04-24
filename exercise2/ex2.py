import sys
from typing import List, Optional, NewType, Set, Dict
import ecdsa  # type: ignore
import hashlib
import secrets
from collections import deque

PublicKey = NewType('PublicKey', bytes)
Signature = NewType('Signature', bytes)
BlockHash = NewType('BlockHash', bytes)  # This will be the hash of a block
TxID = NewType("TxID", bytes)  # this will be a hash of a transaction

GENESIS_BLOCK_PREV = BlockHash(b"Genesis")  # these are the bytes written as the prev_block_hash of the 1st block.

BLOCK_SIZE = 10  # The maximal size of a block. Larger blocks are illegal.


def hash_function(input_bytes: bytes) -> bytes:
    """
    This function hashes the given input bytes, using the SHA256 hash-function.
    It mainly helps avoid writing '.digest()' everywhere...
    :param input_bytes: The input bytes to calculate the hash from.
    :return: The hash of the input bytes.
    """
    return hashlib.sha256(input_bytes).digest()


class Transaction:
    """
    Represents a transaction that moves a single coin.
    A transaction with no source creates money. It will only be created by the miner of a block.
    Instead of a signature, it should have 48 random bytes.
    """

    def __init__(self, output: PublicKey, tx_input: Optional[TxID], signature: Signature) -> None:
        """
        Initialize the transaction object with the given output, input and signature.
        :param output: The output of the transaction, which is the address (a.k.a. public_key)
                       of the recipient.
        :param input: The input of the transaction, which is the transaction ID to use
                      (its output is the sender public_key).
        :param signature: The signature of the sender, which uses the private_key associated
                          with the input-transaction's output public_key.
                          The message that is being signed is the concatenation of the
                          recipient's public_key and the input transaction ID.
        """
        self.output: PublicKey = output  # DO NOT change these field names.
        self.input: Optional[TxID] = tx_input  # DO NOT change these field names.
        self.signature: Signature = signature  # DO NOT change these field names.

    def get_txid(self) -> TxID:
        """
        Returns the identifier of this transaction. This is the sha256 of the transaction contents.
        :return: The ID of this transaction, which is the hash of the concatenation of
                 the output, input and the signature.
                 Note that if the input is None then it's regarded as empty bytes in the concatenation.
        """

        input_bytes = bytes() if self.input is None else self.input
        tx_content = self.output + input_bytes + self.signature
        tx_id = TxID(hash_function(tx_content))
        return tx_id


class Block:
    """
    This class represents a block.
    """

    def __init__(self,
                 previous_block_hash: BlockHash,
                 transactions: Optional[List[Transaction]] = None) -> None:
        """
        Initialize the Block object with the given transactions and previous block-hash.
        :param previous_block_hash: The block-hash of the previous block in the blockchain.
        :param transactions: The list of transactions to insert into this block.
                             If not given - the default is an empty-list.
        """
        # This is done to avoid using mutable values as a default argument (i.e. transactions=list()).
        if transactions is None:
            transactions = list()

        self.previous_block_hash: BlockHash = previous_block_hash
        self.transactions: List[Transaction] = transactions

    def get_transactions_hash(self):
        """
        Get the hash of all of the transactions in the block.
        The hash is the merkle-tree root.
        We handle cases of odd number of children by duplicating the transaction, as described in:
        https://bitcoin.stackexchange.com/questions/46767/merkle-tree-structure-for-9-transactions
        """
        # If there are no transactions in the block, return the hash "nothing" (i.e. empty bytes).
        if len(self.transactions) == 0:
            return hash_function(bytes())

        # If there is only one transaction in the block, the hash of the transactions is just its
        # TxID (which is already the hash of the transaction).
        if len(self.transactions) == 1:
            return self.transactions[0].get_txid()

        # Now we know that there are at least 2 transactions in the block, so let's create the merkle-tree.

        # The will serve as a queue (FIFO data-structure) to process the tree from to bottom to the top.
        curr_queue = deque([bytes(tx.get_txid()) for tx in self.transactions])

        # As long as the queue contains at least 2 elements, hash every pair and insert
        # it to the right hand-side of the queue.
        while len(curr_queue) >= 2:
            # The amount of times the for-loop will execute is n // 2, and if
            # n is odd then the last transaction is repeated to form a "pair" of transactions.
            n = len(curr_queue)
            for i in range(0, n, 2):
                left_txid = curr_queue.popleft()
                right_txid = curr_queue.popleft() if i + 1 < n else left_txid

                curr_hash = hash_function(left_txid + right_txid)
                curr_queue.append(curr_hash)

        # Now we know that the queue has only one element, so it's the root of the merkle tree.
        merkle_root = curr_queue.pop()

        return merkle_root

    def get_block_hash(self) -> BlockHash:
        """
        Gets the hash of this block, which is the hash of the concatenation of the previous block-hash
        and the transactions' hash (i.e. the merkle root).
        :return: The hash of this block.
        """
        transactions_hash = self.get_transactions_hash()
        block_hash = BlockHash(hash_function(self.previous_block_hash + transactions_hash))

        return block_hash

    def get_transactions(self) -> List[Transaction]:
        """
        :return: The list of transactions in this block.
        """
        return self.transactions

    def get_prev_block_hash(self) -> BlockHash:
        """
        :return: The hash of the previous block
        """
        return self.previous_block_hash


class Node:
    def __init__(self) -> None:
        """
        Creates a new node with an empty mempool and no connections to others.
        Blocks mined by this nodes will reward the miner with a single new coin,
        created out of thin air and associated with the mining reward address.
        """
        self.blockchain: List[Block] = list()
        self.mempool: List[Transaction] = list()

        # This is the list of unspent transactions (to validate that new transactions
        # that are entering the MemPool use an unspent input).
        self.utxo: List[Transaction] = list()

        # This is used in order to get the block given the BlockHash in O(1),
        # instead of iterating the blockchain which takes O(len(blockchain)).
        self.block_hash_to_index: Dict[BlockHash, int] = dict()

        self.private_key: ecdsa.SigningKey = ecdsa.SigningKey.generate()
        self.public_key: PublicKey = PublicKey(self.private_key.get_verifying_key().to_der())

        # These are the TxIDs of the transactions in the blockchain that their output is this Node's public_key.
        self.coins: List[TxID] = list()

        # These are the TxIDs of the transactions in the blockchain that their output is this Node's public_key.
        # BUT - this Node didn't use them already in creating new transactions
        # (that maybe didn't made it into the blockchain yet).
        self.unspent_coins: List[TxID] = list()

        # The index of the last block we read in the blockchain to update the Node's balance.
        self.last_block_index_used_for_update: int = -1

        self.connections: Set[Node] = set()

    def get_tx_index_in_utxo(self, transaction: Transaction) -> int:
        """
        Get the index of the transaction in the UTxO that its TxID matches the TxID of the given transaction.
        :param transaction: The transaction to search
        :return: The index of the transaction in the UTxO that its TxID matches the TxID of the given transaction.
                 In case the transaction was not found, return -1.
        """
        for i, tx in enumerate(self.utxo):
            if tx.get_txid() == transaction.input:
                return i

        return -1

    def connect(self, other: 'Node') -> None:
        """Connects this node to another node for block and transaction updates.
        Connections are bi-directional, so the other node is connected to this one as well.
        Raises an exception if asked to connect to itself.
        The connection itself does not trigger updates about the mempool,
        but nodes instantly notify of their latest block to each other."""
        # Check if the given Node is equal to this Node. Equality is determined by the manually specified
        # __eq__ function, which state that two Node are equal if they have the same public-key.
        if self == other:
            raise ValueError("Can not add the Node as a connection of itself.")

        self.connections.add(other)
        other.connections.add(self)  # TODO is it needed? I think so...
        # see https://moodle2.cs.huji.ac.il/nu19/mod/forum/discuss.php?d=64212#p92698

    def disconnect_from(self, other: 'Node') -> None:
        """Disconnects this node from the other node. If the two were not connected, then nothing happens."""
        if other in self.connections:
            self.connections.remove(other)
            other.connections.remove(self)  # TODO is it needed? I think so...
            # see https://moodle2.cs.huji.ac.il/nu19/mod/forum/discuss.php?d=64212#p92698

    def get_connections(self) -> Set['Node']:
        """Returns a set of the connections of this node."""
        return self.connections

    def add_transaction_to_mempool(self, transaction: Transaction) -> bool:
        """
        This function inserts the given transaction to the mempool.
        It is used by a Node's connections to inform it of a new transaction.
        It will return False iff any of the following conditions hold:
        (i) The transaction is invalid (the signature fails).
        (ii) The source doesn't have the coin that he tries to spend.
        (iii) There is contradicting tx in the mempool.
        """
        # Verify that the input of the transaction (which is a TxID) exists in the UTxO.
        # If so - get its index (used later to extract the public-key for verifying the signature).
        tx_index_in_utxo: int = self.get_tx_index_in_utxo(transaction)
        if tx_index_in_utxo == -1:  # This means the transaction's input TxID was not found in the UTxO.
            return False

        input_transaction: Transaction = self.utxo[tx_index_in_utxo]
        public_key: PublicKey = input_transaction.output

        # Verify that the transaction is valid, using the public-key as a verifying key and the
        # (transaction's input + transaction's output) as the data that was signed.
        try:
            ecdsa.VerifyingKey.from_der(public_key).verify(signature=transaction.signature,
                                                           data=transaction.output + transaction.input)
        except ecdsa.BadSignatureError:
            return False

        # Verify that there is no contradicting transaction in the MemPool.
        # This means a transaction that uses the input TxID (disallow double-spending).
        for tx in self.mempool:
            if tx.input == transaction.input:
                return False

        # All conditions hold, now we can safely add the transaction to the MemPool.
        self.mempool.append(transaction)

        return True

    def notify_of_block(self, block_hash: BlockHash, sender: 'Node') -> None:
        """
        This method is used by a node's connection to inform it that it has learned of a
        new block (or created a new block). If the block is unknown to the current Node, the block is requested.
        We assume the sender of the message is specified, so that the node can choose to request this block if
        it wishes to do so.
        If it is part of a longer unknown chain, these blocks are requested as well, until reaching a known block.
        Upon receiving new blocks, they are processed and and checked for validity (check all signatures, hashes,
        block size, etc).
        If the block is on the longest chain, the mempool and UTxO set change accordingly.
        If the block is indeed the tip of the longest chain,
        a notification of this block is sent to the neighboring nodes of this node.
        No need to notify of previous blocks -- the nodes will fetch them if needed.

        A reorg may be triggered by this block's introduction. In this case the UTxO set is rolled back to the split point,
        and then rolled forward along the new branch.
        The mempool is similarly emptied of transactions that cannot be executed now.
        """
        raise NotImplementedError()

    def get_money_creation_transaction(self) -> Transaction:
        """
        This function inserts a transaction into the mempool that creates a single coin out of thin air. Instead of a signature,
        this transaction includes a random string of 48 bytes (so that every two creation transactions are different).
        generate these random bytes using secrets.token_bytes(48).
        We assume only the bank calls this function (wallets will never call it).
        """
        return Transaction(output=self.public_key, tx_input=None, signature=secrets.token_bytes(48))

    def mine_block(self) -> BlockHash:
        """"
        This function allows the node to create a single block. It is called externally by the tests.
        The block should contain BLOCK_SIZE transactions (unless there aren't enough in the mempool). Of these,
        BLOCK_SIZE-1 transactions come from the mempool and one additional transaction will be included that creates
        money and adds it to the address of this miner.
        Money creation transactions have None as their input, and instead of a signature, contain 48 random bytes.
        If a new block is created, all connections of this node are notified by calling their notify_of_block() method.
        The method returns the new block hash.
        """
        # The transactions that will be added to the blockchain are the first limit transactions in the MemPool.
        transactions_to_add: List[Transaction] = self.mempool[:BLOCK_SIZE-1]

        # Remove the transactions from the MemPool.
        self.mempool = self.mempool[BLOCK_SIZE-1:]

        # Add the money-creation transaction to the the block.
        transactions_to_add.append(self.get_money_creation_transaction())

        # Generate a new block and append it to the blockchain.
        block: Block = Block(previous_block_hash=self.get_latest_hash(), transactions=transactions_to_add)
        block_hash: BlockHash = block.get_block_hash()
        self.block_hash_to_index.update({block_hash: len(self.blockchain)})
        self.blockchain.append(block)

        # Add the new transactions to the UTxO.
        # Note the not all the transactions in transactions_to_add are un-spent,
        # but this will be fixed in the next for-loop.
        self.utxo.extend(transactions_to_add)

        # Remove the transactions in the UTxO that were spent in any of the transaction in the transactions that
        # were added to the blockchain.
        self.utxo = [unspent_tx for unspent_tx in self.utxo
                     if not any(unspent_tx.get_txid() == tx.input for tx in transactions_to_add)]

        return block_hash

    def get_block(self, block_hash: BlockHash) -> Block:
        """
        :param block_hash: The hash of the block to retrieve.
        :return: A block object given its hash.
                 If the block doesnt exist, a ValueError is raised.
        """
        index_in_blockchain = self.block_hash_to_index.get(block_hash)

        if index_in_blockchain is not None:
            return self.blockchain[index_in_blockchain]

        raise ValueError("The given block_hash does not exist in the blockchain.")

    def get_latest_hash(self) -> BlockHash:
        """
        This function returns the hash of the block that is the current tip of the longest chain.
        If no blocks were created, return GENESIS_BLOCK_PREV.
        :return: The last block hash the was created.
        """
        # If there are no blocks in the blockchain, return the hash of the genesis block.
        if len(self.blockchain) == 0:
            return GENESIS_BLOCK_PREV

        return self.blockchain[-1].get_block_hash()

    def get_mempool(self) -> List[Transaction]:
        """
        :return: The list of transactions that are waiting to be included in blocks.
        """
        return self.mempool

    def get_utxo(self) -> List[Transaction]:
        """
        :return: The list of unspent transactions.
        """
        return self.utxo

    def create_transaction(self, target: PublicKey) -> Optional[Transaction]:
        """
        This function returns a signed transaction that moves an unspent coin to the target.
        It chooses the coin based on the unspent coins that this node owns.
        If the node already tried to spend a specific coin, and such a transaction exists in its mempool,
        but it did not yet get into the blockchain then the node should'nt try to spend it again until clear_mempool() is
        called -- which will wipe the mempool and thus allow the node to attempt these re-spends.
        The method returns None if there are no outputs that have not been spent already.
        The transaction is added to the mempool (and as a result it is also published to connected nodes).
        """
        if len(self.unspent_coins) == 0:
            return None

        selected_coin: TxID = self.unspent_coins.pop()
        transaction: Transaction = Transaction(output=target,
                                               tx_input=selected_coin,
                                               signature=self.private_key.sign(target + selected_coin))

        addition_to_mempool_was_successful = self.add_transaction_to_mempool(transaction)

        assert addition_to_mempool_was_successful, "Addition to the MemPool failed. WTF?"  # TODO remove

        # TODO Is it legit? Is it possible that this transaction will be rejected according to another node MemPool?
        if addition_to_mempool_was_successful:
            for node in self.connections:
                addition_to_other_node_mempool_was_successful = node.add_transaction_to_mempool(transaction)
                assert addition_to_other_node_mempool_was_successful, "WTF? see the TODO above..."  # TODO remove

        return transaction

    def clear_mempool(self) -> None:
        """
        Clears this nodes mempool. All transactions waiting to be entered into the next block are cleared.
        """
        self.mempool.clear()
        self.unspent_coins = self.coins[:]

    def get_balance(self) -> int:
        """
        This function returns the number of coins that this node owns according to its view of the blockchain.
        Coins that the node owned and sent away will still be considered as part of the balance until the spending
        transaction is in the blockchain.

        :return: The number of coins that this wallet has (according to its view of the blockchain).
        """
        return len(self.coins)

    def get_address(self) -> PublicKey:
        """
        :return: The public address of this node in DER format (follow the code snippet in the pdf of ex1).
        """
        return self.public_key

    # TODO are the two functions below really needed? comment-out and check...
    def __hash__(self):
        """
        This function is implemented to enable storing the Node object in hashable containers (such as a set).
        :return: The hash of this Node object.
        """
        return int.from_bytes(self.public_key, byteorder=sys.byteorder)
        # return self.public_key

    def __eq__(self, other):
        """
        This function is implemented to enable storing the Node object in hashable containers (such as a set).
        :param other: Another Node to check equality to.
        :return: True if and only if the other node has the same public_key.
        """
        return self.public_key == other.public_key


"""
Importing this file should NOT execute code. It should only create definitions for the objects above.
Write any tests you have in a different file.
You may add additional methods, classes and files but be sure no to change the signatures of methods
included in this template.
"""

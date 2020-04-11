from typing import List, Optional, NewType, Dict
import ecdsa  # type: ignore
import hashlib
import secrets
from collections import deque

PublicKey = NewType('PublicKey', bytes)
Signature = NewType('Signature', bytes)
BlockHash = NewType('BlockHash', bytes)  # This will be the hash of a block
TxID = NewType("TxID", bytes)  # this will be a hash of a transaction

GENESIS_BLOCK_PREV = BlockHash(b"Genesis")  # these are the bytes written as the prev_block_hash of the 1st block.


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
    Represents a transaction that moves a single coin
    A transaction with no source creates money. It will only be created by the bank.
    """

    def __init__(self, output: PublicKey, input: Optional[TxID], signature: Signature) -> None:
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
        self.input: Optional[TxID] = input  # DO NOT change these field names.
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


class Bank:
    """
    This class represents the bank.
    """

    def __init__(self) -> None:
        """
        Initialize a bank with an empty blockchain and an empty mempool.
        """
        self.mempool: List[Transaction] = list()
        self.blockchain: List[Block] = list()

        # This is the list of unspent transactions (to validate that new transactions
        # that are entering the MemPool use an unspent input).
        self.utxo: List[Transaction] = list()

        # This is used in order to get the block given the BlockHash in O(1),
        # instead of iterating the blockchain which takes O(len(blockchain)).
        self.block_hash_to_index: Dict[BlockHash, int] = dict()

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

    def add_transaction_to_mempool(self, transaction: Transaction) -> bool:
        """
        This function inserts the given transaction to the mempool.
        It will return False iff any of the following conditions hold:
        (i) the transaction is invalid (the signature fails)
        (ii) the source doesn't have the coin that he tries to spend
        (iii) there is contradicting tx in the mempool.

        :param transaction: The transaction to add.
        :return: True if the addition to the MemPool was successful.
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

    def end_day(self, limit: int = 10) -> BlockHash:
        """
        This function tells the bank that the day ended,
        and that the first `limit` transactions in the mempool should be committed to a block.
        If there are fewer than 'limit' transactions in the mempool, a smaller block is created.
        If there are no transactions, an empty block is created.
        The hash of this new block is returned.

        :param limit: The maximal number of transactions to insert into the new block.
        :return: The hash of the block that was created.
        """
        # The transactions that will be added to the blockchain are the first limit transactions in the MemPool.
        transactions_to_add: List[Transaction] = self.mempool[:limit]

        # Remove the transactions from the MemPool.
        self.mempool = self.mempool[limit:]

        # Generate a new block and append it to the blockchain.
        block: Block = Block(previous_block_hash=self.get_latest_hash(), transactions=transactions_to_add)
        block_hash: BlockHash = block.get_block_hash()
        self.block_hash_to_index.update({block_hash: len(self.blockchain)})
        self.blockchain.append(block)

        # Add the new transactions to the UTxO.
        # Note the not all the transactions in transactions_to_add are un-spent,
        # but this will be fixed in the next for-loop.
        # TODO test inserting a chain of transactions to the MemPool.
        # TODO Alice --> Bob --> Charlie --> Dan
        # TODO Only Dan's transaction should remain in the MemPool.
        self.utxo.extend(transactions_to_add)

        # Remove the transactions in the UTxO that were spent in any of the transaction in the transactions that
        # were added to the blockchain.
        for unspent_tx in self.utxo[:]:
            if any(unspent_tx.get_txid() == tx.input for tx in transactions_to_add):
                self.utxo.remove(unspent_tx)

        return block.get_block_hash()

    def get_block(self, block_hash: BlockHash) -> Block:
        """
        :param block_hash: The hash of the block to retrieve.
        :return: A block object given its hash.
                 If the block doesnt exist, an exception is thrown.
        """
        index_in_blockchain = self.block_hash_to_index.get(block_hash)

        if index_in_blockchain is not None:
            return self.blockchain[index_in_blockchain]

        raise KeyError("The given block_hash does not exist in the blockchain.")

    def get_latest_hash(self) -> BlockHash:
        """
        :return: The last block hash the was created.
        """
        # If there are no blocks in the blockchain, return the hash of the genesis block.
        if len(self.blockchain) == 0:
            return GENESIS_BLOCK_PREV

        return self.blockchain[-1].get_block_hash()

    def get_mempool(self) -> List[Transaction]:
        """
        :return: The list of transactions that didn't enter any block yet.
        """
        return self.mempool

    def get_utxo(self) -> List[Transaction]:
        """
        :return: The list of unspent transactions.
        """
        return self.utxo

    def create_money(self, target: PublicKey) -> None:
        """
        This function inserts a transaction into the mempool that creates a single coin out of thin air. Instead of a signature,
        this transaction includes a random string of 48 bytes (so that every two creation transactions are different).
        generate these random bytes using secrets.token_bytes(48).
        We assume only the bank calls this function (wallets will never call it).

        :param target: The recipient of the created money.
        """
        random_bytes = secrets.token_bytes(48)
        transaction = Transaction(output=target,
                                  input=None,
                                  signature=random_bytes)

        self.mempool.append(transaction)


class Wallet:
    """
    The Wallet class. Each wallet controls a single private key, and has a single corresponding public key (address).
    Wallets keep track of the coins owned by them, and can create transactions to move these coins.
    """

    def __init__(self) -> None:
        """
        Initialize a new wallet with a new private key.
        """
        self.private_key = ecdsa.SigningKey.generate()
        self.public_key: PublicKey = PublicKey(self.private_key.get_verifying_key().to_der())

        # These are the TxIDs of the transactions in the blockchain that their output is this Wallet's public_key.
        self.coins: List[TxID] = list()

        # These are the TxIDs of the transactions in the blockchain that their output is this Wallet's public_key.
        # BUT - this Wallet didn't use them already in creating new transactions
        # (that maybe didn't made it into the blockchain yet).
        self.unspent_coins: List[TxID] = list()

        # The index of the last block we read in the blockchain to update the Wallet's balance.
        self.last_block_index_used_for_update: int = -1

    def update(self, bank: Bank) -> None:
        """
        This function updates the balance allocated to this wallet by querying the bank.
        Don't read all of the bank's utxo, but rather process the blocks since the last update one at a time.
        For this exercise, there is no need to validate all transactions in the block

        :param bank: The bank to update from.
        """
        # first build a list of blocks until our latest update.
        blocks_to_read: List[Block] = bank.blockchain[self.last_block_index_used_for_update + 1:]

        # Create 2 lists - coins to add and coins_to_remove.
        # coins_to_add are the coins in the new blocks in the blockchain that are assigned to this wallet.
        # coins_to_remove are the coins in the new blocks in the blockchain that this wallet used.
        coins_to_add: List[TxID] = list()
        coins_to_remove: List[TxID] = list()
        for block in blocks_to_read:
            for tx in block.get_transactions():
                if tx.output == self.public_key:
                    coins_to_add.append(tx.get_txid())
                # TODO test a transaction to myself.
                if tx.input in self.coins:
                    coins_to_remove.append(tx.input)

        # Remove the coins that were spent in transactions that made it into the blockchain.
        self.coins = [coin for coin in self.coins if coin not in coins_to_remove]
        self.unspent_coins = [coin for coin in self.unspent_coins if coin not in coins_to_remove]

        # Add the coins that were sent to this address, found in transactions in the blockchain
        # (in the relevant part of the blockchain, meaning from the last time we updated).
        self.coins.extend(coins_to_add)
        self.unspent_coins.extend(coins_to_add)

        self.last_block_index_used_for_update = len(bank.blockchain) - 1

    def create_transaction(self, target: PublicKey) -> Optional[Transaction]:
        """
        This function returns a signed transaction that moves an unspent coin to the target.
        It chooses the coin based on the unspent coins that this wallet had since the last update.
        If the wallet already spent a specific coin, then he should'nt spend it again until unfreeze_all() is called.
        The method returns None if there are no outputs that have not been spent already.

        :param target: The recipient of this transaction.
        :return: The transaction, or None if this wallet has no coins to spend.
        """
        if len(self.unspent_coins) == 0:
            return None

        selected_coin: TxID = self.unspent_coins.pop()
        transaction: Transaction = Transaction(output=target,
                                               input=selected_coin,
                                               signature=self.private_key.sign(target + selected_coin))

        return transaction

    def unfreeze_all(self) -> None:
        """
        Allows the wallet to try to re-spend outputs that it created transactions for (unless these outputs already
        made it into the blockchain).
        """
        self.unspent_coins = self.coins[:]

    def get_balance(self) -> int:
        """
        This function returns the number of coins that this wallet has.
        It will return the balance that is relevant until the last call to update.
        Coins that the wallet owned and sent away will still be considered as part of the balance until the spending
        transaction is in the blockchain.

        :return: The number of coins that this wallet has.
        """
        return len(self.coins)

    def get_address(self) -> PublicKey:
        """
        :return: The public address of this wallet in DER format (follow the code snippet in the pdf).
        """
        return self.public_key

# importing this file should NOT execute code. It should only create definitions for the objects above.
# Write any tests you have in a different file.
# You may add additional methods, classes and files
# but be sure no to change the signatures of methods included in this template.

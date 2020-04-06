from typing import List, Optional, NewType
import ecdsa  # type: ignore
import hashlib
import secrets

PublicKey = NewType('PublicKey', bytes)
Signature = NewType('Signature', bytes)
BlockHash = NewType('BlockHash', bytes)  # This will be the hash of a block
TxID = NewType("TxID", bytes)  # this will be a hash of a transaction

GENESIS_BLOCK_PREV = BlockHash(b"Genesis")  # these are the bytes written as the prev_block_hash of the 1st block.


class Transaction:
    """Represents a transaction that moves a single coin
    A transaction with no source creates money. It will only be created by the bank."""

    def __init__(self, output: PublicKey, input: Optional[TxID], signature: Signature) -> None:
        self.output: PublicKey = output  # DO NOT change these field names.
        self.input: Optional[TxID] = input  # DO NOT change these field names.
        self.signature: Signature = signature  # DO NOT change these field names.

    def get_txid(self) -> TxID:
        """Returns the identifier of this transaction. This is the sha256 of the transaction contents."""
        # TODO what to return if the id is null?
        return hashlib.sha256(self.input)


class Block:
    """This class represents a block."""

    transactions_list = None
    prev_block_hash = None

    def __init__(self, prev_block_hash, transactions_list):
        self.prev_block_hash = prev_block_hash
        self.transactions_list = transactions_list

    def get_block_hash(self) -> BlockHash:
        """Gets the hash of this block"""

        hash = hashlib.sha256()
        hash.update(self.prev_block_hash)

        # Calculate block hash by passing all over the transaction id and hash them
        for tx in self.transactions_list:
            hash.update(tx.input)
        return BlockHash(hash)

    def get_transactions(self) -> List[Transaction]:
        """
        returns the list of transactions in this block.
        """
        return self.transactions_list

    def get_prev_block_hash(self) -> BlockHash:
        """Gets the hash of the previous block"""
        return self.prev_block_hash


class Bank:

    hash_to_blocks = {}
    public_key_to_money = {}
    mempool = None
    blockchain = None

    def __init__(self) -> None:
        """Creates a bank with an empty blockchain and an empty mempool."""
        self.mempool = list()
        self.blockchain = list()

    def add_transaction_to_mempool(self, transaction: Transaction) -> bool:
        """
        This function inserts the given transaction to the mempool.
        It will return False iff any of the following conditions hold:
        (i) the transaction is invalid (the signature fails)
        (ii) the source doesn't have the coin that he tries to spend
        (iii) there is contradicting tx in the mempool.
        """
        # Check if signature is valid
        if ecdsa.VerifyingKey.from_der(transaction.output).verify(transaction.signature, transaction.input):
            return False
        # source = self.public_key_to_money.get(transaction.)

        # todo deals with the other cases


        self.mempool.append(transaction)
        return True

    def end_day(self, limit: int = 10) -> BlockHash:
        """
         This function tells the bank that the day ended,
         and that the first `limit` transactions in the mempool should be committed to a block.
         If there are fewer than 'limit' transactions in the mempool, a smaller block is created.
         If there are no transactions, an empty block is created.
         The hash of this new block is returned.
         """
        counter = limit
        transaction_list = list()
        for transaction in self.mempool:
            if counter == 0:
                break
            transaction_list.append(transaction)
            counter -= 1

        pre_block_hash = self.get_latest_hash()
        new_block = Block(pre_block_hash, transaction_list)

        self.update_source_money(transaction_list)
        self.blockchain.append(new_block) # Add the new block to the block chain (todo needs to do it now?)

        hash_new_block = new_block.get_block_hash()
        self.hash_to_blocks.update({hash_new_block, new_block}) # Add the new block with its hash to hash_to_block dict
        return hash_new_block


    def get_block(self, block_hash: BlockHash) -> Block:
        """
        This function returns a block object given its hash. If the block doesnt exist, an exception is thrown..
        """
        block = self.hash_to_blocks.get(block_hash)
        # TODO id the block hash is genesis blockHash what block should we return?
        if not block:
            raise Exception() # todo Change to another exception type
        return block

    def get_latest_hash(self) -> BlockHash:
        """
        This function returns the last block hash the was created.
        """
        last_block = self.blockchain[-1]
        if not last_block:
            return GENESIS_BLOCK_PREV # If there is not block yet, return the first genesis block
        return last_block.get_block_hash()

    def get_mempool(self) -> List[Transaction]:
        """
        This function returns the list of transactions that didn't enter any block yet.
        """
        return self.mempool

    def get_utxo(self) -> List[Transaction]:
        """
        This function returns the list of unspent transactions.
        """
        raise NotImplementedError()

    def create_money(self, target: PublicKey) -> None:
        """
        This function inserts a transaction into the mempool that creates a single coin out of thin air. Instead of a signature,
        this transaction includes a random string of 48 bytes (so that every two creation transactions are different).
        generate these random bytes using secrets.token_bytes(48).
        We assume only the bank calls this function (wallets will never call it).
        """
        raise NotImplementedError()

    def update_source_money(self, transactions_list):
        for transaction in transactions_list:
            source = transaction.output # Gets the public key of the receiver
            if source in self.public_key_to_money:
                num_coins = self.public_key_to_money[source]
                self.public_key_to_money[source] = num_coins + 1
            else:
                self.public_key_to_money.update({source:1})




class Wallet:
    """The Wallet class. Each wallet controls a single private key, and has a single corresponding public key (address).
    Wallets keep track of the coins owned by them, and can create transactions to move these coins."""

    private_key = None
    public_key = None  # todo maybe need to use the object PublicKey in the above file???
    number_coins = 0

    def __init__(self) -> None:
        """
        This function generates a new wallet with a new private key.
        """
        self.private_key = ecdsa.SigningKey.generate()
        self.public_key = PublicKey(self.private_key.get_verifying_key().to_der())

    def update(self, bank: Bank) -> None:
        """
        This function updates the balance allocated to this wallet by querying the bank.
        Don't read all of the bank's utxo, but rather process the blocks since the last update one at a time.
        For this exercise, there is no need to validate all transactions in the block
        """
        # first build a list of blocks until our latest update.
        raise NotImplementedError()

    def create_transaction(self, target: PublicKey) -> Optional[Transaction]:
        """
        This function returns a signed transaction that moves an unspent coin to the target.
        It chooses the coin based on the unspent coins that this wallet had since the last update.
        If the wallet already spent a specific coin, then he should'nt spend it again until unfreeze_all() is called.
        The method returns None if there are no outputs that have not been spent already.
        """
        # todo The method returns None if there are no outputs that have not been spent already.
        # signature = self.private_key.sign(TxID)  # todo needs to sign the entire tx
        # return Transaction(target, TxID, signature)

    def unfreeze_all(self) -> None:
        """
        Allows the wallet to try to re-spend outputs that it created transactions for (unless these outputs already
        made it into the blockchain).
        """
        raise NotImplementedError()

    def get_balance(self) -> int:
        """
        This function returns the number of coins that this wallet has.
        It will return the balance that is relevant until the last call to update.
        Coins that the wallet owned and sent away will still be considered as part of the balance until the spending
        transaction is in the blockchain.
        """
        return self.number_coins

    def get_address(self) -> PublicKey:
        """
        This function returns the public address of this wallet in DER format (follow the code snippet in the pdf).
        """
        return self.public_key

# importing this file should NOT execute code. It should only create definitions for the objects above.
# Write any tests you have in a different file.
# You may add additional methods, classes and files but be sure no to change the signatures of methods included in this template.

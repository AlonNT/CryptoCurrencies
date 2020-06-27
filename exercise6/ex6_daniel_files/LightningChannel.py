import web3
import time
import eth_account.messages
import web3.contract
from contract_info import  *


w3 = web3.Web3(web3.HTTPProvider("http://127.0.0.1:7545"))
APPEAL_PERIOD = 3  # the appeal period in blocks.

TestContract = w3.eth.contract(abi=ABI, bytecode=compiled_sol["object"])

class LightningNode:
    def __init__(self, my_account):
        """
        Initializes a new node that uses the given local ethereum account to move money
        :param my_account:
        """
        self.account_address = my_account
        self.contracts = {}


    def get_address(self):
        """
        Returns the address of this node on the blockchain (its ethereum wallet).
        :return:
        """
        return self.account_address

    def establish_channel(self, other_party_address, amount_in_wei):
        """
        Sets up a channel with another user at the given ethereum address.
        Returns the address of the contract on the blockchain.
        :param other_party_address:
        :param amount_in_wei:
        :return: returns the contract address on the blockchain
        """
        txn_dict = {
            'from': self.account_address,
            'value': amount_in_wei }

        # Submit the transaction that deploys the contract
        tx_hash = TestContract.constructor(other_party_address, APPEAL_PERIOD).transact(txn_dict)

        # Wait for the transaction to be mined, and get the transaction receipt
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        contract_address = tx_receipt.contractAddress

        # Create the contract instance with the newly-deployed address
        contract = w3.eth.contract(address=contract_address ,abi=ABI)

        # Add the contract's details to the contracts dictionary
        self.contracts[contract_address] = {
            "other_party" : other_party_address,
            "channel_balance" : amount_in_wei,
            "contract": contract,
            "node_number": 0,
            "last_message": [0, 0]
        }

        return contract_address

    def notify_of_channel(self, contract_address):
        """
        A function that is called when someone created a channel with you and wants to let you know.
        :param contract_address:
        :return:
        """
        # According the forum - the user that establishes the channel is the one that deposits the funds

        # Create the contract instance with the newly-deployed address
        contract = w3.eth.contract(address=contract_address, abi=ABI)

        # Gets the owner and the balance of the deployed contract
        other_party_address = contract.functions.get_owner1_address().call()
        amount_in_wei = contract.functions.get_balance().call()

        # Add the contract details to the contract dictionary
        self.contracts[contract_address] = {
            "other_party" : other_party_address,
            "channel_balance" : amount_in_wei,
            "contract": contract,
            "node_number": 1,
            "last_message": [0, 0]}

    def send(self, contract_address, amount_in_wei, other_node):
        """
        Sends money to the other address in the channel, and notifies the other node (calling its recieve()).
        :param contract_address:
        :param amount_in_wei:
        :param other_node:
        :return:
        """

        last_message = self.contracts[contract_address]["last_message"]
        node_number = self.contracts[contract_address]["node_number"]
        channel_balance = self.contracts[contract_address]["channel_balance"]

        # Check if there is enough money in the channel
        new_serial_number = last_message[1] + 1
        if node_number == 0 and last_message[0] + amount_in_wei <= channel_balance:
            message = [last_message[0] + amount_in_wei, new_serial_number]
        elif node_number == 1 and last_message[0] - amount_in_wei >= 0:
            message = [last_message[0] - amount_in_wei, new_serial_number]
        else:
            #TODO do we need to throw an exception ?
            return

        message_types = ['uint256', 'int8']
        signature = self.sign(message, message_types, self.account_address)

        other_node_signature = other_node.receive((message, message_types, signature, contract_address))

        # Check if the signature of the node is valid
        if (other_node_signature is not None) and (self.check_signature(message, message_types, other_node_signature,
                                                                        other_node.account_address)):
            self.contracts[contract_address]["other_owner_last_signature"] = other_node_signature
            self.contracts[contract_address]["last_message"] = message


    def receive(self, state_msg):
        """
        A function that is called when you've received funds.
        You are sent the message about the new channel state that is signed by the other user
        :param state_msg:
        :return: a state message with the signature of this node acknowledging the transfer.
        """
        message, message_types, sender_signature, contract_address = state_msg
        other_party_address = self.contracts[contract_address]["other_party"]
        last_message = self.contracts[contract_address]["last_message"]
        channel_balance = self.contracts[contract_address]["channel_balance"]
        node_index = self.contracts[contract_address]["node_number"]


        # Checks if the signature is correct
        if self.check_signature(message, message_types, sender_signature, other_party_address) and (message[1] > last_message[1] and
            ((node_index == 0 and message[0] <= last_message[0]) or (node_index == 1 and message[0] >= last_message[0])) and message[0] <= channel_balance):
            # TODO Check this!!!!
            self.contracts[contract_address]["other_owner_last_signature"] = sender_signature
            self.contracts[contract_address]["last_message"] = message
            signature = self.sign(message, message_types, self.account_address)
            return signature
        else:
            return None

    def unilateral_close_channel(self, contract_address, channel_state = None):
        """
        Closes the channel at the given contract address.
        :param contract_address:
        :param channel_state: this is the latest state which is signed by the other node, or None,
        if the channel is to be closed using its initial balance allocation.
        :return:
        """
        contract = self.contracts[contract_address]["contract"]
        tx_dict = {"from": self.account_address}

        if channel_state is None:
            contract.functions.default_split().transact(tx_dict)
        else:
            balance, serial_num, v, r, s = channel_state
            contract.functions.one_sided_close(balance, serial_num, v, r, s).transact(tx_dict)


    def get_current_signed_channel_state(self, chan_contract_address):
        """
        Gets the state of the channel (i.e., the last signed message from the other party)
        :param chan_contract_address:
        :return:
        """

        # Gets the last message & signature from the contract
        last_message = self.contracts[chan_contract_address]["last_message"]
        last_signature = self.contracts[chan_contract_address]["other_owner_last_signature"]

        # Decompose the signature to 3 numbers that are accepted by ethereum
        v, r, s = self.get_v_r_s(last_signature)
        balance, serial_number = last_message
        return (balance, serial_number, v, r, s)

    def appeal_closed_chan(self, contract_address):
        """
        Checks if the channel at the given address needs to be appealed. If so, an appeal is sent to the blockchain.
        :param contract_address:
        :return:
        """
        last_message = self.contracts[contract_address]["last_message"]
        contract = self.contracts[contract_address]["contract"]

        # Check if the serial numbers of the last message is newer. if it does an appeal can occur
        if contract.functions.get_last_serial().call() < last_message[1]:
            txn_dict = {"from": self.account_address}
            balance, serial_number, v, r, s = self.get_current_signed_channel_state(contract_address)
            contract.functions.appeal_closure(balance, serial_number, v, r, s).transact(txn_dict)



    def withdraw_funds(self, contract_address):
        """
        Allows the user to withdraw funds from the contract into his address.
        :param contract_address:
        :return:
        """

        contract = self.contracts[contract_address]["contract"]
        tx_dict = {"from": self.account_address}

        # Call the contract function to withdraw the money to account address
        tx_hash = contract.functions.withdraw_funds(self.account_address).transact(tx_dict)

        # Wait for the transaction to be mined, and get the transaction receipt
        txn_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        # todo maybe print it ?
        if txn_receipt is None:
            return {'status': 'failed', 'error': 'timeout'}

        return {'status': 'added', 'txn_receipt': txn_receipt}


    def debug(self, contract_address):
        """
        A useful debugging method. prints the values of all variables in the contract. (public variables have auto-generated getters).
        :param contract_address:
        :return:
        """

    def sign(self, message, message_types, signer_account):
        """
        This function signs a message by the given signer account.
        The account is assumed to be unlocked (i.e., its private keys are managed by
        the connected ethereum node). The message is given as a list of values, and
        the message types is a list of strings that describe their types in solidity.
        See example:

        sig1 = sign([3,4], ['uint256', 'uint256'], w3.eth.accounts[0])
        #Produces a signature on the values 3,4 which are of type uint256, by the given account.
        """
        message_hash = web3.Web3.soliditySha3(message_types, message)
        return w3.eth.sign(signer_account, message_hash)



    def check_signature(self, message, message_types, sig, signerPubKey):
        """
        Checks a given signature on a given message by a given public key
        The message is given as a list of values, and the message types
        is a list of strings that describe their types in solidity.
        See example:

        check_sig([3,4], ['uint256', 'uint256'], sig1, w3.eth.accounts[0])
        #checks that the signature provided is a signeature on the message 3,4 by the pubkey of accounts[0]
        """
        h1 = web3.Web3.soliditySha3(message_types, message)  # we reconstruct the message hash
        message_hash = eth_account.messages.defunct_hash_message(h1)  # this is the digest that ethereum actually signs
        return w3.eth.account.recoverHash(message_hash, signature=sig) == signerPubKey

    def get_v_r_s(self, signature):
        """
        Converts the signature to = 3 numbers that are accepted by ethereum
        :param signature:
        :return:
        """
        return web3.Web3.toInt(signature[-1]) + 27, web3.Web3.toHex(signature[:32]), web3.Web3.toHex(signature[32:64])


def wait_k_blocks(k: int, sleep_interval: int = 2):
    start = w3.eth.blockNumber
    time.sleep(sleep_interval)
    while w3.eth.blockNumber < start + k:
        time.sleep(sleep_interval)


# Opening and closing channel without sending any money.
def scenario1():
    print("\n\n*** SCENARIO 1 ***")
    print("Creating nodes")
    alice = LightningNode(w3.eth.accounts[0])
    bob = LightningNode(w3.eth.accounts[1])
    print("Creating channel")
    chan_address = alice.establish_channel(bob.get_address(), 10 * 10 ** 18)  # creates a channel between Alice and Bob.
    print("Notifying bob of channel")
    bob.notify_of_channel(chan_address)

    print("channel created", chan_address)

    print("ALICE CLOSING UNILATERALLY")
    alice.unilateral_close_channel(chan_address)

    print("waiting")
    wait_k_blocks(APPEAL_PERIOD)

    print("Bob Withdraws")
    bob.withdraw_funds(chan_address)
    print("Alice Withdraws")
    alice.withdraw_funds(chan_address)

# sending money back and forth and then closing with latest state.
def scenario2():
    print("\n\n*** SCENARIO 2 ***")
    print("Creating nodes")
    alice = LightningNode(w3.eth.accounts[0])
    bob = LightningNode(w3.eth.accounts[1])
    print("Creating channel")
    chan_address = alice.establish_channel(bob.get_address(), 10 * 10**18)  # creates a channel between Alice and Bob.
    print("Notifying bob of channel")
    bob.notify_of_channel(chan_address)

    print("Alice sends money")
    alice.send(chan_address, 2 * 10**18, bob)
    print("Bob sends some money")
    bob.send(chan_address, 1 * 10**18, alice)
    print("Alice sends money twice!")
    alice.send(chan_address, 2 * 10**18, bob)
    alice.send(chan_address, 2 * 10**18, bob)

    print("BOB CLOSING UNILATERALLY")
    bob.unilateral_close_channel(chan_address)

    print("waiting")
    wait_k_blocks(APPEAL_PERIOD)

    print("Bob Withdraws")
    bob.withdraw_funds(chan_address)
    print("Alice Withdraws")
    alice.withdraw_funds(chan_address)

# sending money, alice tries to cheat, bob appeals.
def scenario3():
    print("\n\n*** SCENARIO 3 ***")
    print("Creating nodes")
    alice = LightningNode(w3.eth.accounts[0])
    bob = LightningNode(w3.eth.accounts[1])
    print("Creating channel")
    chan_address = alice.establish_channel(bob.get_address(), 10 * 10**18)  # creates a channel between Alice and Bob.
    print("Notifying bob of channel")
    bob.notify_of_channel(chan_address)

    print("Alice sends money thrice")

    alice.send(chan_address, 1 * 10**18, bob)
    old_state = alice.get_current_signed_channel_state(chan_address)
    alice.send(chan_address, 1 * 10**18, bob)
    alice.send(chan_address, 1 * 10**18, bob)

    print("ALICE TRIES TO CHEAT")
    alice.unilateral_close_channel(chan_address,old_state)

    print("Waiting one blocks")
    wait_k_blocks(1)

    print("Bob checks if he needs to appeal, and appeals if he does")
    bob.appeal_closed_chan(chan_address)

    print("waiting")
    wait_k_blocks(APPEAL_PERIOD)

    print("Bob Withdraws")
    bob.withdraw_funds(chan_address)
    print("Alice Withdraws")
    alice.withdraw_funds(chan_address)

# scenario1()
# scenario2()
scenario3()

import web3
import time
import eth_account.messages
import web3.contract
from contract_info import ABI, compiled_sol


w3 = web3.Web3(web3.HTTPProvider("http://127.0.0.1:7545"))
APPEAL_PERIOD = 3  # The appeal period in blocks.


class ContractWrapper:
    """
    A Wrapper for the contract, being hold by the one of the owners.
    """

    def __init__(self, contract_obj, node_number):
        """
        Initialize a new wrapper for the contract object.

        :param contract_obj: The contract object to wrap.
        :param node_number: The index of the current owner in the channel.
                            0 means we are owner1, and 1 means we are owner2.
        """
        self.contract_obj = contract_obj
        self.node_number = node_number

        # Get the balance by querying the total balance in the channel by calling the function 'get_balance'.
        self.channel_balance = contract_obj.functions.get_balance().call()

        if self.node_number == 0:
            self.other_party_address = self.contract_obj.functions.owner2().call()
        else:
            self.other_party_address = self.contract_obj.functions.owner1().call()

        self.last_serial_number = 0
        self.last_owner2_balance = 0
        self.other_owner_last_signature = None


def check_signature(message, sig, signer_public_key):
    """
    Checks a given signature on a given message by a given public key
    The message is given as a list of values, and the message types
    is a list of strings that describe their types in solidity.
    See example:

    check_sig([3,4], ['uint256', 'uint256'], sig1, w3.eth.accounts[0])
    #checks that the signature provided is a signature on the message 3,4 by the pubkey of accounts[0]
    """
    message_types = ['address', 'uint256', 'int8']
    h1 = web3.Web3.soliditySha3(message_types, message)  # we reconstruct the message hash
    message_hash = eth_account.messages.defunct_hash_message(h1)  # this is the digest that ethereum actually signs
    return w3.eth.account.recoverHash(message_hash, signature=sig) == signer_public_key


def get_v_r_s(signature):
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


class LightningNode:
    def __init__(self, my_account):
        """
        Initializes a new node that uses the given local ethereum account to move money
        :param my_account:
        """
        self.account_address = my_account
        self.contracts = dict()

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
        txn_dict = {'from': self.account_address, 'value': amount_in_wei}

        # Submit the transaction that deploys the contract
        tx_hash = w3.eth.contract(abi=ABI, bytecode=compiled_sol["object"]).constructor(
            other_party_address, APPEAL_PERIOD).transact(txn_dict)

        # Wait for the transaction to be mined, and get the transaction receipt.
        # In case of Timeout - an exception of type web3.exceptions.TimeExhausted is raised,
        # and we don't want to catch it here (raise in upwards). TODO [Alon] should we catch or not?
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        contract_address = tx_receipt.contractAddress

        # Create the contract instance with the newly-deployed address
        contract_obj = w3.eth.contract(address=contract_address, abi=ABI)

        # Add the contract's details to the contracts dictionary
        self.contracts[contract_address] = ContractWrapper(contract_obj, node_number=0)

        return contract_address

    def notify_of_channel(self, contract_address):
        """
        A function that is called when someone created a channel with you and wants to let you know.
        The user that establishes the channel is the one that deposits the funds.
        :param contract_address:
        :return:
        """
        if contract_address not in self.contracts:
            contract_obj = w3.eth.contract(address=contract_address, abi=ABI)
            self.contracts[contract_address] = ContractWrapper(contract_obj, node_number=1)

    def send(self, contract_address, amount_in_wei, other_node):
        """
        Sends money to the other address in the channel, and notifies the other node (calling its receive()).
        :param contract_address:
        :param amount_in_wei:
        :param other_node:
        :return:
        """
        if contract_address not in self.contracts:
            return

        c = self.contracts[contract_address]

        # If we are node number 0 (i.e. owner1) then we are transferring to owner2,
        # so we need to add the amount to the balance of owner2.
        # If we are node number 1 (i.e. owner2) then we are transferring to owner1,
        # so we need to subtract the amount to the balance of owner2.
        sign = 1 if c.node_number == 0 else -1
        updated_owner2_balance = c.last_owner2_balance + sign * amount_in_wei

        # TODO [Alon] What to do here?
        assert 0 <= updated_owner2_balance <= c.channel_balance, "Not enough money in the channel."

        # As stated in the forum:
        # https://moodle2.cs.huji.ac.il/nu19/mod/forum/discuss.php?d=98876#p147200
        # The only requirement for a valid serial is that it is strictly larger than the last valid serial,
        # so we simply keep track of the largest seen serial (even if the message is invalid).
        updated_serial_number = c.last_serial_number + 1
        c.last_serial_number = updated_serial_number

        message = [contract_address, updated_owner2_balance, updated_serial_number]
        # message_types = ['address', 'uint256', 'int8']

        signature = self.sign(message)

        other_node_signature = other_node.receive(state_msg=(message, signature))

        # Check if the signature of the node is valid
        if other_node_signature is not None:
            other_node_signature_is_valid = check_signature(message, other_node_signature, other_node.account_address)
            if other_node_signature_is_valid:
                c.other_owner_last_signature = other_node_signature
                c.last_owner2_balance = updated_owner2_balance

    def receive(self, state_msg):
        """
        A function that is called when you've received funds.
        You are sent the message about the new channel state that is signed by the other user
        :param state_msg:
        :return: a state message with the signature of this node acknowledging the transfer.
        """
        message, sender_signature = state_msg
        contract_address, updated_owner2_balance, updated_serial_number = message

        c = self.contracts[contract_address]

        self_is_owner1 = (c.node_number == 0)
        self_is_owner2 = (c.node_number == 1)

        updated_owner2_balance_is_sane = (0 <= updated_owner2_balance <= c.channel_balance)
        self_balance_increased = ((self_is_owner1 and updated_owner2_balance <= c.last_owner2_balance) or
                                  (self_is_owner2 and updated_owner2_balance >= c.last_owner2_balance))
        signature_is_valid = check_signature(message, sender_signature, c.other_party_address)

        if updated_serial_number <= c.last_serial_number:
            return None

        # As stated in the forum:
        # https://moodle2.cs.huji.ac.il/nu19/mod/forum/discuss.php?d=98876#p147200
        # The only requirement for a valid serial is that it is strictly larger than the last valid serial,
        # so we simply keep track of the largest seen serial (even if the message is invalid).
        c.last_serial_number = updated_serial_number

        if signature_is_valid and self_balance_increased and updated_owner2_balance_is_sane:
            # TODO [Daniel] Check this!!!! [Alon] Why?
            c.other_owner_last_signature = sender_signature
            c.last_owner2_balance = updated_owner2_balance
            signature = self.sign(message)
            return signature

        return None  # TODO [Alon] What should we do in this case?

    def unilateral_close_channel(self, contract_address, channel_state=None):
        """
        Closes the channel at the given contract address.

        :param contract_address:
        :param channel_state: This is the latest state which is signed by the other node,
                              or None, if the channel is to be closed using the current balance allocation.
        """
        c = self.contracts[contract_address]

        tx_dict = {"from": self.account_address}

        # If there was not given a channel_state, and the other owner last signature is None,
        # it means that the channel needs to be closed using the default_split function
        # (which gives everything to owner1).
        if (channel_state is None) and (c.other_owner_last_signature is None):
            c.contract_obj.functions.default_split().transact(tx_dict)
        else:
            # If there was not given a channel_state, take the current state as channel_state.
            if channel_state is None:
                channel_state = self.get_current_signed_channel_state(contract_address)

            # Now send the transaction containing a call to the 'one_sided_close' function, using the 'channel_state'.
            balance, serial_num, v, r, s = channel_state
            c.contract_obj.functions.one_sided_close(balance, serial_num, v, r, s).transact(tx_dict)

        # TODO [Alon] Should we wait for the transaction to enter the blockchain?

    def get_current_signed_channel_state(self, chan_contract_address):
        """
        Gets the state of the channel (i.e., the last signed message from the other party)
        :param chan_contract_address:
        :return:
        """
        c = self.contracts[chan_contract_address]

        # Decompose the signature to 3 numbers that are accepted by ethereum
        v, r, s = get_v_r_s(c.other_owner_last_signature)

        return c.last_owner2_balance, c.last_serial_number, v, r, s

    def appeal_closed_chan(self, contract_address):
        """
        Checks if the channel at the given address needs to be appealed.
        If so, an appeal is sent to the blockchain.
        :param contract_address:
        """
        c = self.contracts[contract_address]

        # Check if the channel is closed, and the serial number of the last message is newer.
        # If it does, an appeal can occur.
        channel_is_closed = not c.contract_obj.functions.channel_open().call()
        last_serial_number_in_contract = c.contract_obj.functions.last_serial_num().call()

        if channel_is_closed and (last_serial_number_in_contract < c.last_serial_number):
            txn_dict = {"from": self.account_address}
            balance, serial_number, v, r, s = self.get_current_signed_channel_state(contract_address)
            c.contract_obj.functions.appeal_closure(balance, serial_number, v, r, s).transact(txn_dict)

            # TODO [Alon] Should we wait for the transaction to enter the blockchain?

    def withdraw_funds(self, contract_address):
        """
        Allows the user to withdraw funds from the contract into his address.
        :param contract_address:
        :return:
        """
        c = self.contracts[contract_address]

        # contract = self.contracts[contract_address]["contract"]
        tx_dict = {"from": self.account_address}

        # Call the contract function to withdraw the money to account address
        tx_hash = c.contract_obj.functions.withdraw_funds(self.account_address).transact(tx_dict)

        # Wait for the transaction to be mined, and get the transaction receipt
        txn_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        # TODO [Alon] I don't think that's the way to check for timeout. See above TODOs...
        # TODO [Daniel] Maybe print it ?
        if txn_receipt is None:
            return {'status': 'failed', 'error': 'timeout'}

        return {'status': 'added', 'txn_receipt': txn_receipt}

    def debug(self, contract_address):
        """
        A useful debugging method. prints the values of all variables in the contract.
        (public variables have auto-generated getters).
        :param contract_address:
        :return:
        """
        pass

    def sign(self, message):
        """
        This function signs a message by the given signer account.
        The account is assumed to be unlocked (i.e., its private keys are managed by
        the connected ethereum node). The message is given as a list of values, and
        the message types is a list of strings that describe their types in solidity.
        See example:

        sig1 = sign([3,4], ['uint256', 'uint256'], w3.eth.accounts[0])
        #Produces a signature on the values 3,4 which are of type uint256, by the given account.
        """
        message_types = ['address', 'uint256', 'int8']
        message_hash = web3.Web3.soliditySha3(message_types, message)
        signature = w3.eth.sign(self.account_address, message_hash)

        return signature


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
    alice.unilateral_close_channel(chan_address, old_state)

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


# TODO [Alon] scenario4
# TODO [Alon] Alice is participating in a channel with Bob, and had previously closed a channel with him.
# TODO [Alon] Now Bob closes the channel using a message that belongs to the old channel.
# TODO [Alon] This should fail because the signature is also being done on the channel address


# scenario1()
# scenario2()
scenario3()

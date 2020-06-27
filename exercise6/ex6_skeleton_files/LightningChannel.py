import web3
import time
import eth_account.messages
import web3.contract

w3 = web3.Web3(web3.HTTPProvider("http://127.0.0.1:7545"))
APPEAL_PERIOD = 3  # the appeal period in blocks.

class LightningNode:
    def __init__(self, my_account):
        """
        Initializes a new node that uses the given local ethereum account to move money
        :param my_account:
        """
        pass


    def get_address(self):
        """
        Returns the address of this node on the blockchain (its ethereum wallet).
        :return:
        """

    def establish_channel(self, other_party_address, amount_in_wei):
        """
        Sets up a channel with another user at the given ethereum address.
        Returns the address of the contract on the blockchain.
        :param other_party_address:
        :param amount_in_wei:
        :return: returns the contract address on the blockchain
        """
        return ""

    def notify_of_channel(self, contract_address):
        """
        A function that is called when someone created a channel with you and wants to let you know.
        :param contract_address:
        :return:
        """
        pass

    def send(self, contract_address, amount_in_wei, other_node):
        """
        Sends money to the other address in the channel, and notifies the other node (calling its recieve()).
        :param contract_address:
        :param amount_in_wei:
        :param other_node:
        :return:
        """
        pass

    def receive(self, state_msg):
        """
        A function that is called when you've received funds.
        You are sent the message about the new channel state that is signed by the other user
        :param state_msg:
        :return: a state message with the signature of this node acknowledging the transfer.
        """
        pass

    

    def unilateral_close_channel(self, contract_address, channel_state = None):
        """
        Closes the channel at the given contract address.
        :param contract_address:
        :param channel_state: this is the latest state which is signed by the other node, or None,
        if the channel is to be closed using the current balance allocation.
        :return:
        """
        pass



    def get_current_signed_channel_state(self, chan_contract_address):
        """
        Gets the state of the channel (i.e., the last signed message from the other party)
        :param chan_contract_address:
        :return:
        """
        pass

    def appeal_closed_chan(self, contract_address):
        """
        Chekcs if the channel at the given address needs to be appealed. If so, an appeal is sent to the blockchain.
        :param contract_address:
        :return:
        """
        pass

    def withdraw_funds(self, contract_address):
        """
        Allows the user to withdraw funds from the contract into his address.
        :param contract_address:
        :return:
        """
        pass

    def debug(self, contract_address):
        """
        A useful debugging method. prints the values of all variables in the contract. (public variables have auto-generated getters).
        :param contract_address:
        :return:
        """

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

scenario1()
scenario2()
scenario3()

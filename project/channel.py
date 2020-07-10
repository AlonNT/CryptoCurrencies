from typing import Tuple


class Channel:

    def __init__(self, nodes: Tuple[bytes, bytes], balances: Tuple[int, int],
                 base_fee: int = 0, proportional_fee: int = 0):
        """
        Initialize the channel with the balances and the two nodes in each side of the channel.
        Note that the capacity of the channel is the sum of the two balances.

        :param nodes: A tuple of two bytes-arrays - each is the address of the corresponding node.
        :param balances: A tuple of two integers - each is the balance of the corresponding node in this channel.
        :param base_fee: The base fee of this channel. Each transfer of funds through this channel
                         pays this fee, in addition to the proportional fee (see below).
        :param proportional_fee: The proportional fee of this channel - it's multiplied by the transaction's amount.
        """
        self.nodes: Tuple[bytes, bytes] = nodes
        self.balances: Tuple[int, int] = balances
        self.proportional_fee: int = proportional_fee
        self.base: int = base_fee

    def update_fees(self, base_fee: int, proportional_fee: int):
        """
        Update the fees for the channel.

        :param base_fee: The new base fee.
        :param proportional_fee: The new proportional fee.
        """
        self.proportional_fee: int = proportional_fee
        self.base: int = base_fee

    def transfer(self):
        pass

    # TODO more functions (as we draw in the API).

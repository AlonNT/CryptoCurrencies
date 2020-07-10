# General Insights, Ideas & Questions
## References
- Hijacking Routes in Payment Channel Networks: A Predictability Tradeoff
   - [paper](https://arxiv.org/pdf/1909.06890.pdf)
   - [medium post](https://medium.com/blockchains-huji/route-hijacking-and-dos-in-off-chain-networks-37ce6f54aa26)
   - [code](https://github.cs.huji.ac.il/saart/saart-lightning)
- Congestion Attacks in Payment Channel Networks
   - [paper](https://arxiv.org/pdf/2002.06564.pdf)
   - [medium post](https://medium.com/blockchains-huji/congestion-attacks-in-payment-channel-networks-b7ac37208389)
   - [code](https://github.com/ayeletmz/Lightning-Network-Congestion-Attacks)
- [Coindesk: You can now get paid (a little) for using bitcoin’s lightning network.](https://www.coindesk.com/you-can-now-get-paid-a-little-for-using-bitcoins-lightning-network)
- [Lightning network: how to explore the topology](https://medium.com/coinmonks/lightning-network-how-to-explore-the-topology-32f234f4287f)
- [Basis of Lightning Technology (BOLT)](https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md)

#### Python Packages
- [NetworkX](https://networkx.github.io/documentation/latest/tutorial.html)

## Questions
- **Routing Algorithms**
  - What exactly is **recursive** in the routing formulas given in the paper 
    *Hijacking Routes in Payment Channel Networks: A Predictability Tradeoff*?
  - Does the amounts which go through each channel change depending on the fees? 
    We need to understand the following paragraph:
    ```text
    ...
    lnd chooses the path of minimum weight, 
    calculated using the following recursive formula, 
    where p is the list of channels in this path, 
    and ams is the list of amounts the go through 
    each channel (changes depending on the fees)
    ...
    ```
- How does the fee splits between the two nodes of this channel?
  There are several possibilities, such as 50-50 or relative to the current state of the channel 
  (which is known to the two parties). 
  - Our guess is that it splits relative to the current state of the channel. **TODO: VERIFY** 
- How do nodes in the Lightning network discover the structure of the network's graph? 
  - This includes the nodes, channels, and their capacities. 
  - Maybe they discover it from their neighbors (that discover it from their neighbors, etc). 
  - When does this information updated?
    - Foe example, assume some new node joins the network and connects to several other nodes. When will the entire
      network will be aware of its existence? A quote from the paper
      ```text
      ...
      In order to find such a path, nodes leverage the knowledge
      of the channel graph which is continuously gossiped about by
      nodes in the network. Given this knowledge of the network
      graph, nodes utilize source routing to pick their path.
      ...
      ```


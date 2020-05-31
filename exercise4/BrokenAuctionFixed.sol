pragma solidity ^0.5.8;

contract Auction {
    address payable private highestBidder;
    string highest_Bidder_name;
    uint private highestBid;
    address payable private owner;
    mapping (address => uint) pendingWithdrawals;


    constructor() public payable {
        owner = msg.sender;
    }

    function bid(string memory name) public payable {
        require(msg.value >= highestBid);

        if (highestBidder != address(0)) {
            pendingWithdrawals[highestBidder] += msg.value;
            highest_Bidder_name = name;
        }

       highestBidder = msg.sender;
       highestBid = msg.value;
    }

    function withdraw() public {
        uint amount = pendingWithdrawals[msg.sender];
        // Remember to zero the pending refund before sending to prevent re-entrancy attacks
        pendingWithdrawals[msg.sender] = 0;
        msg.sender.transfer(amount);
    }

    function terminate_auction() external payable {
        require(msg.sender == owner);
        owner.transfer(highestBid);
    }

    function get_cur_winner() view external returns(address payable){
        return highestBidder;
    }

    function get_highest_bid() view external returns(uint) {
        return highestBid;
    }

    function get_bidder_name() view external returns(string memory){
        return highest_Bidder_name;
    }

}

pragma solidity ^0.5.8;

contract Auction {
    address payable private highestBidder;
    string highest_Bidder_name;
    uint private highestBid;
    address payable private owner;
    mapping (address => uint) pendingWithdrawals;
    bool auctionEnded;  // It is initialized as false by default.

    constructor() public payable {
        owner = msg.sender;
    }

    function bid(string memory name) public payable {
        require(!auctionEnded, "Too late, the auction was ended.");
        require(msg.value >= highestBid, "There is already a higher bid, try harder!");

        if (highestBidder != address(0)) {
            pendingWithdrawals[highestBidder] += highestBid;
            highest_Bidder_name = name;
        }

       highestBidder = msg.sender;
       highestBid = msg.value;
    }

    function withdraw() public {
        uint amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        msg.sender.transfer(amount);
    }

    function end_auction() external payable {
        require(msg.sender == owner, "You are not the owner of the auction, so you can not end it.");
        require(!auctionEnded, "The auction was already ended, so you can not end it.");
        auctionEnded = true;
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

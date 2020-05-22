pragma solidity ^0.5.8;

contract Auction {
    address payable private highestBidder;
    string highest_Bidder_name;
    uint private highestBid;

    function bid(string memory name) public payable {
        require(msg.value >= highestBid);

        if (highestBidder != address(0)) {
            highestBidder.transfer(highestBid); // if this call consistently fails, no one else can bid
            highest_Bidder_name = name;
        }

       highestBidder = msg.sender;
       highestBid = msg.value;
    }
    
    function get_cur_winner() view external returns(address payable){
        return highestBidder;
    }
    
    function get_highest_bid() view external returns(uint){
        return highestBid;
    }
    
    function get_bidder_name() view external returns(string memory){
        return highest_Bidder_name;
    }
}

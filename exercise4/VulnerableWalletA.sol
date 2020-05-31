pragma solidity ^0.5.8;

contract Wallet{
    mapping (address => uint) private userBalances;
    uint public value;
    address public bidder;

    function deposit() public payable {
        value = msg.value;
        bidder = msg.sender;
        userBalances[msg.sender] = msg.value;
    }

    function withdrawBalance() public {
        uint amountToWithdraw = userBalances[msg.sender];
        value = amountToWithdraw;
        userBalances[msg.sender] = 0;
        // At this point, the caller's default function may be executed, and can call withdrawBalance again
        (bool res,) = msg.sender.call.value(amountToWithdraw)("");
        require(res);

    }
}

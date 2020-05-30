pragma solidity ^0.5.8;

contract Wallet{
    mapping (address => uint) private userBalances;

    function deposit() public payable{
        userBalances[msg.sender] = msg.value;
    }
    
    function withdrawBalance() public {
        uint amountToWithdraw = userBalances[msg.sender];
        (bool res,) = msg.sender.call.value(amountToWithdraw)(""); // At this point, the caller's default function may be executed, and can call withdrawBalance again
        require(res);
        userBalances[msg.sender] = 0;
    }
}
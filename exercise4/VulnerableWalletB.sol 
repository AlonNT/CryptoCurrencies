pragma solidity ^0.5.8;

contract Wallet{
    mapping (address => uint) private userBalances;
    mapping (address => uint) private userCalls;

    function deposit() public payable{
		userCalls[msg.sender] = 0;
        userBalances[msg.sender] = msg.value;
    }

    function withdrawBalance() public {
		if (userCalls[msg.sender] == 0) {
			userCalls[msg.sender] = 1;
			uint amountToWithdraw = userBalances[msg.sender];
			(bool res,) = msg.sender.call.value(amountToWithdraw)(""); // At this point, the caller's default function may be executed, and can call withdrawBalance again
			require(res);
			userBalances[msg.sender] = 0;
			userCalls[msg.sender] = 0;
		}
    }
}

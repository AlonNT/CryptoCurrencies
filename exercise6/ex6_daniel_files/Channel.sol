pragma solidity ^0.5.9;

// this is a skeleton file for the channel contract. Feel free to change as you wish. 
contract Channel{

    address payable public owner1;
    address payable public owner2;
    uint private appeal_period_len;
    mapping (address => uint256) private userBalances; 
    int8 private last_serial_num;
    bool private channel_open;
    uint block_number_init;

    //Notice how this modifier is used below to restrict access. Create more if you need them!
    modifier onlyOwners{
        require(msg.sender == owner1 || msg.sender == owner2,
            "Only an owner can call this function.");
        _;
    }

    constructor(address payable _other_owner, uint _appeal_period_len) payable public{
        appeal_period_len = _appeal_period_len;
        owner1 = msg.sender;
        owner2 = _other_owner;
        channel_open = true;
    }

    function default_split() onlyOwners external{
        // closes the channel according to a default_split, gives the money to party 1. starts the appeal process.
        if (channel_open == true) {
            userBalances[owner1] = address(this).balance;
            block_number_init = block.number; 
            last_serial_num = 0;
            channel_open = false;
        }
    }

    function one_sided_close(uint256 balance, int8 serial_num , uint8 v, bytes32 r, bytes32 s) onlyOwners external{
        //closes the channel based on a message by one party. starts the appeal period
        
        // Needs to verfiy the signature of the other node
        address signerPubKey = owner2;
        if (msg.sender == owner2) {
            signerPubKey = owner1;
        }
        if (channel_open == true && verify_sig(balance, serial_num, v, r, s, signerPubKey) == true) {
            userBalances[owner1] = address(this).balance - balance;
            userBalances[owner2] = balance;
            last_serial_num = serial_num;
            block_number_init = block.number; 
            channel_open = false;
        }
    }
    
    function appeal_closure(uint256 balance, int8 serial_num , uint8 v, bytes32 r, bytes32 s) onlyOwners external{
        // appeals a one_sided_close. should show a newer signature. only useful within the appeal period
        
        // Needs to verfiy the signature of the other node
        address signerPubKey = owner2;
        if (msg.sender == owner2) {
            signerPubKey = owner1;
        }
        
        // Checks if the channel is closed,  the serial number of the transaction is newer and the signature is valid
        if (channel_open == false && verify_sig(balance, serial_num, v, r, s, signerPubKey) && serial_num > last_serial_num) {
            userBalances[owner1] = address(this).balance - balance;
            userBalances[owner2] = balance;
            last_serial_num = serial_num;
        }
    }

    function withdraw_funds(address payable dest_address) onlyOwners external{
        //withdraws the money of msg.sender to the address he requested. Only used after appeals are done.
        if (channel_open == false){ // if channel is still open we cant withdraw the money yet
        
            // Checks if the appeal periud is over
            if (block.number - block_number_init >= appeal_period_len) {
                uint amount = userBalances[msg.sender];
                dest_address.transfer(amount);
            }
        }
    }

    function () external payable{
        revert();  // we make this contract non-payable. Money can only be added at creation.
    }
    
    function verify_sig(uint256 balance, int8 serial_num, uint8 v, bytes32 r, bytes32 s, address signerPubKey) pure public returns (bool) {
        bytes32 hashMessage = keccak256(abi.encodePacked(balance, serial_num));
        bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashMessage));
        return ecrecover(messageDigest, v, r, s) == signerPubKey;
    }
    
    function get_balance() public view returns(uint256) {
        return address(this).balance;
    }
    
    function get_owner1_address() public view returns(address) {
        return owner1;
    }
    
    function get_last_serial() public view returns(int) { 
        return last_serial_num;
    }
}
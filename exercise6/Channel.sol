pragma solidity ^0.5.9;

contract Channel {

	// The one that opened the channel (and deposited the initial funds).
    address payable public owner1;
    address payable public owner2;

    // After 'appeal_period_len' blocks the funds can be withdrawn 
    // (and no appeal can be made).
    uint public appeal_period_len;

    // This mapping holds the balances of each of the owners, that 
    // can be withdrawn (after the appeal period ends).
    mapping (address => uint256) private userBalances; 

    // The serial number of the last split of the balance between 
    // the two owners.
    // One of the owners can appeal with a different balances split 
    // with a larger serial number.
    int8 public last_serial_num;

    bool public channel_open;     // Is the channel open or closed.
    uint public block_number_at_closure;  // The block number at closure.

    modifier onlyOwners{
        require(msg.sender == owner1 || msg.sender == owner2, 
        	"Only an owner can call this function.");
        _;
    }

    modifier openChannel{
        require(channel_open, 
        	"This function must be called when the channel is open.");
        _;
    }

    modifier closedChannel{
        require(!channel_open, 
        	"This function must be called when the channel is open.");
        _;
    }

    modifier appealPeriod{
        require(block.number - block_number_at_closure < appeal_period_len,
            "This function must be called during the appeal period.");
        _;
    }

    modifier appealPeriodEnded{
        require(block.number - block_number_at_closure >= appeal_period_len,
            "This function must be called after the appeal period ends.");
        _;
    }

    constructor(address payable _other_owner, 
    	uint _appeal_period_len) payable public {
        require(msg.value > 0, 
            "The channel must be initialized with some money.");
        require(msg.sender != _other_owner, 
            "Cannot have a channel connecting to youself.");

        owner1 = msg.sender;
        owner2 = _other_owner;
        appeal_period_len = _appeal_period_len;
        channel_open = true;
    }

    function default_split() onlyOwners openChannel external {
        // Closes the channel according to a default_split, 
        // gives the money to party 1. 
        // Starts the appeal process.
        channel_open = false;
        block_number_at_closure = block.number; 
        userBalances[owner1] = address(this).balance;
        userBalances[owner2] = 0;
        last_serial_num = 0;
    }

    function one_sided_close(uint256 balance, int8 serial_num , 
    	                     uint8 v, bytes32 r, bytes32 s) 
             onlyOwners openChannel external {
        //closes the channel based on a message by one party. 
        // starts the appeal period
        require(balance <= address(this).balance, 
            "balance can not be greater than the balance in the channel.");

        // Needs to verfiy the signature of the other node
        address signerPubKey = (msg.sender == owner1) ? owner2 : owner1;
        require(verify_sig(balance, serial_num, v, r, s, signerPubKey), 
            "Signatue verification failed.");

        channel_open = false;
        block_number_at_closure = block.number; 
        userBalances[owner1] = address(this).balance - balance;
        userBalances[owner2] = balance;
        last_serial_num = serial_num;
    }
    
    function appeal_closure(uint256 balance, int8 serial_num , 
    	                    uint8 v, bytes32 r, bytes32 s) 
             onlyOwners closedChannel appealPeriod external {
        // appeals a one_sided_close. should show a newer signature. 
        // only useful within the appeal period
        require(balance <= address(this).balance, 
            "balance can not be greater than the balance in the channel.");
        
        // Needs to verfiy the signature of the other node
        address signerPubKey = (msg.sender == owner1) ? owner2 : owner1;
        require(verify_sig(balance, serial_num, v, r, s, signerPubKey), 
            "Signatue verification failed.");
        require(serial_num > last_serial_num, 
            "Serial number is not larger than the serial number at closure.");

        // Checks if the channel is closed,  the serial number of the 
        // transaction is newer and the signature is valid
        userBalances[owner1] = address(this).balance - balance;
        userBalances[owner2] = balance;
        last_serial_num = serial_num;
    }

    function withdraw_funds(address payable dest_address) 
             onlyOwners closedChannel appealPeriodEnded external {
        //withdraws the money of msg.sender to the address he requested. 
        // Only used after appeals are done.
        dest_address.transfer(userBalances[msg.sender]);
    }

    function () external payable{
        revert();  // we make this contract non-payable. 
                   //Money can only be added at creation.
    }
    
    function verify_sig(uint256 balance, int8 serial_num, 
    	                uint8 v, bytes32 r, bytes32 s, address signerPubKey) 
             view public returns (bool) {
        bytes32 hashMessage = keccak256(abi.encodePacked(address(this), 
        	                            balance, serial_num));
        bytes32 messageDigest = keccak256(
        	abi.encodePacked("\x19Ethereum Signed Message:\n32", hashMessage));
        return ecrecover(messageDigest, v, r, s) == signerPubKey;
    }
    
    function get_balance() public view returns(uint256) {
        return address(this).balance;
    }
}
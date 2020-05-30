pragma solidity ^0.5.8;

contract MyFirstContract{
    
    int private val;
    string private name;
    address public owner;

    event NewValue(int value, string p_name);
    
    constructor(int value, string memory my_name) public{
        owner = msg.sender;
        val = value;
        name = my_name;
    }
    
    function get_val() view external returns(int){
        return val;
    }
    
    function get_name() view external returns(string memory){
        return name;
    }
    
    function set_val(int) external{
        require(msg.sender == owner, "not the owner, cant change the value");
        val +=1;
        emit NewValue(val, name);
    }
}

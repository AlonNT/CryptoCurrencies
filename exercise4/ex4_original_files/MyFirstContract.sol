pragma solidity ^0.5.8;

contract MyFirstContract{
    
    int private val;
    string private name;

    event NewValue(int value, string p_name);
    
    constructor(int value, string memory my_name) public{
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
        val +=1;
        emit NewValue(val, name);
    }
}

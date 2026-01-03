// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "Failed");

        balances[msg.sender] = 0;
    }
}

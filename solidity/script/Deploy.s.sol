// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MessageRelayRegistry.sol";

contract Deploy is Script {
    function run() external returns (MessageRelayRegistry registry) {
        vm.startBroadcast();
        registry = new MessageRelayRegistry();
        vm.stopBroadcast();
    }
}

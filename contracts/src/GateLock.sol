// SPDX-License-Identifier: MIT
pragma solidity =0.8.26;

contract GateLock {
    // the layout of what we will compress
    struct Values {
        uint64 firstValue;
        uint160 secondValue;
        bool is_unlocked;
    }

    struct Payload {
        uint64 firstValue;
        uint160 secondValue;
    }

    error invalidLength();

    mapping(uint id => uint64 random) internal _a;
    mapping(address id => uint56 random) internal _b;
    mapping(uint id => Values values) internal valueMap;
    mapping(bytes32 id => uint128 random) internal _c;
    uint immutable internal totalLength;

    constructor(Payload[] memory initPayload) {
        uint length = initPayload.length;
        totalLength = length;

        uint slot = 0;

        for (uint i = 0; i < length; i++) {
            Payload memory cur = initPayload[i];
            Values memory s = Values(cur.firstValue, cur.secondValue, false);

            valueMap[slot] = s;

            if (cur.firstValue % 2 == 0) {
                slot = cur.firstValue;
            } else {
                slot = cur.secondValue;
            }
        }
    }

    function isSolved(uint[] calldata ids) public view returns (bool res) {
        res = true;

        uint length = ids.length;

        if (length != totalLength) {
            revert invalidLength();
        }

        for (uint i = 0; i < length; i++) {
            res = res && valueMap[ids[i]].is_unlocked;
        }

        return res;
    }
}

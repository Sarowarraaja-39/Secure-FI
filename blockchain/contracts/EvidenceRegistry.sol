// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Local development registry. A digest proves neither truth nor compliance.
contract EvidenceRegistry {
    address public owner;

    struct Record {
        uint256 blockNumber;
        uint256 recordedAt;
        address recorder;
    }

    mapping(bytes32 => Record) private records;
    event EvidenceAnchored(bytes32 indexed digest, address indexed recorder);

    constructor() {
        owner = msg.sender;
    }

    function anchor(bytes32 digest) external {
        require(msg.sender == owner, "Only registry owner");
        require(digest != bytes32(0), "Empty digest");
        require(records[digest].recordedAt == 0, "Already recorded");
        records[digest] = Record(block.number, block.timestamp, msg.sender);
        emit EvidenceAnchored(digest, msg.sender);
    }

    function verify(bytes32 digest) external view returns (uint256, uint256, address) {
        Record memory record = records[digest];
        return (record.blockNumber, record.recordedAt, record.recorder);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.17;

import {IERC20, SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {MerkleProof} from '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';
import '@openzeppelin/contracts/security/ReentrancyGuard.sol';
import {IMerkleDistributor} from './interfaces/IMerkleDistributor.sol';

error AlreadyClaimed();
error InvalidProof();

interface IVestingFactory {
    function deploy_vesting_contract(address token, address account, uint256 amount, uint256 duration) external;
}

contract MerkleDistributor is IMerkleDistributor, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public immutable override token;
    bytes32 public immutable override merkleRoot;
    IVestingFactory public immutable factory;
    address public immutable yfi;
    uint256 public immutable duration;

    // This is a packed array of booleans.
    mapping(uint256 => uint256) private claimedBitMap;

    constructor(address token_, bytes32 merkleRoot_, address factory_, address yfi_, uint256 duration_) {
        token = token_; // YFI
        merkleRoot = merkleRoot_;
        factory = IVestingFactory(factory_); // https://etherscan.io/address/0x200C92Dd85730872Ab6A1e7d5E40A067066257cF#code
        duration = duration_; //152 days (5 months)
    }

    function isClaimed(uint256 index) public view override returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);
    }

    function claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) public virtual override nonReentrant {
        require(account != address(0), 'Invalid account address');
        require(amount > 0, 'Amount must be greater than zero');
        if (isClaimed(index)) revert AlreadyClaimed();

        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        if (!MerkleProof.verify(merkleProof, merkleRoot, node)) revert InvalidProof();

        // Mark it claimed and send the token.
        _setClaimed(index);
        factory.deploy_vesting_contract(
            token,
            account,
            amount,
            duration * 24 * 60 * 60 //duration in days converted to seconds
        );

        emit Claimed(index, account, amount);
    }
}

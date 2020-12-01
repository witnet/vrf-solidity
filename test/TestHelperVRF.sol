// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "../contracts/VRF.sol";


/**
 * @title Test Helper for the VRF contract
 * @dev The aim of this contract is twofold:
 * 1. Raise the visibility modifier of VRF contract functions for testing purposes
 * 2. Removal of the `pure` modifier to allow gas consumption analysis
 * @author Witnet Foundation
 */
contract TestHelperVRF {

  function decodeProof(bytes memory _proof) public pure returns (uint[4] memory) {
    return VRF.decodeProof(_proof);
  }

  function decodePoint(bytes memory _point) public pure returns (uint[2] memory) {
    return VRF.decodePoint(_point);
  }

  function computeFastVerifyParams(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message)
    public pure returns (uint256[2] memory, uint256[4] memory)
  {
    return VRF.computeFastVerifyParams(_publicKey, _proof, _message);
  }

  function verify(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message) public pure returns (bool) {
    return VRF.verify(_publicKey, _proof, _message);
  }

  function fastVerify(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message,
    uint256[2] memory _uPoint,
    uint256[4] memory _vComponents)
  public pure returns (bool)
  {
    return VRF.fastVerify(
      _publicKey,
      _proof,
      _message,
      _uPoint,
      _vComponents);
  }

  function gammaToHash(uint256 _gammaX, uint256 _gammaY) public pure returns (bytes32) {
    return VRF.gammaToHash(_gammaX, _gammaY);
  }

}
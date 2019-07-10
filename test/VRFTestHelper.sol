pragma solidity ^0.5.0;

import "../contracts/VRF.sol";


contract VRFTestHelper is VRF {

  function _verify(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message)
  public returns (bool)
  {
    return verify(_publicKey, _proof, _message);
  }

  function _fastVerify(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message,
    uint256[2] memory _uPoint,
    uint256[4] memory _vComponents)
  public returns (bool)
  {
    return fastVerify(
      _publicKey,
      _proof,
      _message,
      _uPoint,
      _vComponents);
  }

  function _decodeProof(bytes memory _proof) public returns (uint[4] memory) {
    return decodeProof(_proof);
  }

  function _decodePoint(bytes memory _point) public returns (uint[2] memory) {
    return decodePoint(_point);
  }

  function _computeFastVerifyParams(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message)
  public returns (uint256[2] memory, uint256[4] memory)
  {
    return computeFastVerifyParams(_publicKey, _proof, _message);
  }

}
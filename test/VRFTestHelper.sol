pragma solidity ^0.5.0;

import "../contracts/VRF.sol";

/**
 * @title Test Helper for the VRF contract
 * @dev The aim of this contract is twofold:
 * 1. Raise the visibility modifier of VRF contract functions for testing purposes
 * 2. Removal of the `pure` modifier to allow gas consumption analysis
 * @author Witnet Foundation
 */


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

  function _hashToTryAndIncrement(uint256[2] memory _publicKey, bytes memory _message) public pure returns (uint, uint) {
    return hashToTryAndIncrement(_publicKey, _message);
  }

  function _hashPoints(
    uint256 _hPointX,
    uint256 _hPointY,
    uint256 _gammaX,
    uint256 _gammaY,
    uint256 _uPointX,
    uint256 _uPointY,
    uint256 _vPointX,
    uint256 _vPointY)
  public pure returns (bytes16)
  {
    return hashPoints(
      _hPointX,
      _hPointY,
      _gammaX,
      _gammaY,
      _uPointX,
      _uPointY,
      _vPointX,
      _vPointY);
  }

  function _encodePoint(uint256 _x, uint256 _y) public pure returns (bytes memory) {
    return encodePoint(_x, _y);
  }

  function _ecMulSubMul(
    uint256 _scalar1,
    uint256 _a1,
    uint256 _a2,
    uint256 _scalar2,
    uint256 _b1,
    uint256 _b2)
  public pure returns (uint256, uint256)
  {
    return ecMulSubMul(
      _scalar1,
      _a1,
      _a2,
      _scalar2,
      _b1,
      _b2);
  }

  function _ecMulVerify(
    uint256 _scalar,
    uint256 _x,
    uint256 _y,
    uint256 _qx,
    uint256 _qy)
  public pure returns(bool)
  {
    return ecMulVerify(
      _scalar,
      _x,
      _y,
      _qx,
      _qy);
  }
}
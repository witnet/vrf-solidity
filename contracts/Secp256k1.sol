pragma solidity ^0.5.0;

import "./EllipticCurve.sol";

/**
 * @title Secp256k1 Elliptic Curve
 * @dev Secp256k1 Elliptic Curve supporting point derivation function
 * @author Witnet Foundation
 */


contract Secp256k1 is EllipticCurve {

  uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  uint256 constant AA = 0;
  uint256 constant BB = 7;
  uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  /// @dev Public Key derivation from private key
  /// @param _d The scalar
  /// @param _x The coordinate x
  /// @param _y The coordinate y
  /// @return (qx, qy) The derived point
  function derivePoint(uint256 _d, uint256 _x, uint256 _y) public pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = ecMul(
      _d,
      _x,
      _y,
      AA,
      PP
    );
  }
}
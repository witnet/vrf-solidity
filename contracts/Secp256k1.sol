pragma solidity ^0.5.0;

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";


/**
 * @title Secp256k1 Elliptic Curve
 * @dev Secp256k1 Elliptic Curve supporting point derivation function.
 * @author Witnet Foundation
 */
contract Secp256k1 is EllipticCurve {

  // Generator coordinate `x` of EC equation
  uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  // Generator coordinate `y` of EC equation
  uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  // Constant `a` of EC equation
  uint256 constant AA = 0;
  // Constant `B` of EC equation
  uint256 constant BB = 7;
  // Prime number of the curve
  uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
  // Order of the curve
  uint256 constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  /// @dev Public key derivation from private key.
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

  /// @dev Function to derive the `y` coordinate given the `x` coordinate and the parity byte (`0x03` for odd `y` and `0x04` for even `y`).
  /// @param _yByte The parity byte following the ec point compressed format
  /// @param _x The coordinate `x` of the point
  /// @return The coordinate `y` of the point
  function deriveY(uint8 _yByte, uint256 _x) public pure returns (uint256) {
    require(_yByte == 0x02 || _yByte == 0x03, "Invalid compressed EC point prefix");

    return deriveY(
      _yByte,
      _x,
      AA,
      BB,
      PP);
  }
}
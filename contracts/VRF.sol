pragma solidity ^0.5.0;

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";


/**
 * @title Verifiable Random Functions (VRF)
 * @notice Library verifying VRF proofs using the `Secp256k1` curve and the `SHA256` hash function.
 * @dev This library follows the algorithms described in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04) and [RFC6979](https://tools.ietf.org/html/rfc6979).
 * It supports the _SECP256K1_SHA256_TAI_ cipher suite, i.e. the aforementioned algorithms using `SHA256` and the `Secp256k1` curve.
 * @author Witnet Foundation
 */
library VRF {

  /**
   * Secp256k1 parameters
   */

  // Generator coordinate `x` of the EC curve
  uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  // Generator coordinate `y` of the EC curve
  uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  // Constant `a` of EC equation
  uint256 constant AA = 0;
  // Constant `b` of EC equation
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
  function derivePoint(uint256 _d, uint256 _x, uint256 _y) internal pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = EllipticCurve.ecMul(
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
  function deriveY(uint8 _yByte, uint256 _x) internal pure returns (uint256) {
    return EllipticCurve.deriveY(
      _yByte,
      _x,
      AA,
      BB,
      PP);
  }

  /// @dev Computes the VRF hash output as result of the digest of a ciphersuite-dependent prefix
  /// concatenated with the gamma point
  /// @param _gammaX The x-coordinate of the gamma EC point
  /// @param _gammaY The y-coordinate of the gamma EC point
  /// @return The VRF hash ouput as shas256 digest
  function gammaToHash(uint256 _gammaX, uint256 _gammaY) internal pure returns (bytes32) {
    bytes memory c = abi.encodePacked(
      // Cipher suite code (SECP256K1-SHA256-TAI is 0xFE)
      uint8(0xFE),
      // 0x01
      uint8(0x03),
      // Compressed Gamma Point
      encodePoint(_gammaX, _gammaY));

    return sha256(c);
  }

  /// @dev VRF verification by providing the public key, the message and the VRF proof.
  /// This function computes several elliptic curve operations which may lead to extensive gas consumption.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @return true, if VRF proof is valid
  function verify(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message) internal pure returns (bool) {
    // Step 2: Hash to try and increment (outputs a hashed value, a finite EC point in G)
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);

    // Step 3: U = s*B - c*Y (where B is the generator)
    (uint256 uPointX, uint256 uPointY) = ecMulSubMul(
      _proof[3],
      GX,
      GY,
      _proof[2],
      _publicKey[0],
      _publicKey[1]);

    // Step 4: V = s*H - c*Gamma
    (uint256 vPointX, uint256 vPointY) = ecMulSubMul(
      _proof[3],
      hPoint[0],
      hPoint[1],
      _proof[2],
      _proof[0],_proof[1]);

    // Step 5: derived c from hash points(...)
    bytes16 derivedC = hashPoints(
      hPoint[0],
      hPoint[1],
      _proof[0],
      _proof[1],
      uPointX,
      uPointY,
      vPointX,
      vPointY);

    // Step 6: Check validity c == c'
    return uint128(derivedC) == _proof[2];
  }

  /// @dev VRF fast verification by providing the public key, the message, the VRF proof and several intermediate elliptic curve points that enable the verification shortcut.
  /// This function leverages the EVM's `ecrecover` precompile to verify elliptic curve multiplications by decreasing the security from 32 to 20 bytes.
  /// Based on the original idea of Vitalik Buterin: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @param _uPoint The `u` EC point defined as `U = s*B - c*Y`
  /// @param _vComponents The components required to compute `v` as `V = s*H - c*Gamma`
  /// @return true, if VRF proof is valid
  function fastVerify(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message,
    uint256[2] memory _uPoint,
    uint256[4] memory _vComponents)
  internal pure returns (bool)
  {
    // Step 2: Hash to try and increment -> hashed value, a finite EC point in G
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);

    // Step 3 & Step 4:
    // U = s*B - c*Y (where B is the generator)
    // V = s*H - c*Gamma
    if (!ecMulSubMulVerify(
      _proof[3],
      _proof[2],
      _publicKey[0],
      _publicKey[1],
      _uPoint[0],
      _uPoint[1]) ||
      !ecMulVerify(
        _proof[3],
        hPoint[0],
        hPoint[1],
        _vComponents[0],
        _vComponents[1]) ||
      !ecMulVerify(
        _proof[2],
        _proof[0],
        _proof[1],
        _vComponents[2],
        _vComponents[3])
      )
    {
      return false;
    }
    (uint256 vPointX, uint256 vPointY) = EllipticCurve.ecSub(
      _vComponents[0],
      _vComponents[1],
      _vComponents[2],
      _vComponents[3],
      AA,
      PP);

    // Step 5: derived c from hash points(...)
    bytes16 derivedC = hashPoints(
      hPoint[0],
      hPoint[1],
      _proof[0],
      _proof[1],
      _uPoint[0],
      _uPoint[1],
      vPointX,
      vPointY);

    // Step 6: Check validity c == c'
    return uint128(derivedC) == _proof[2];
  }

  /// @dev Decode VRF proof from bytes
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @return The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  function decodeProof(bytes memory _proof) internal pure returns (uint[4] memory) {
    require(_proof.length == 81, "Malformed VRF proof");
    uint8 gammaSign;
    uint256 gammaX;
    uint128 c;
    uint256 s;
    assembly {
      gammaSign := mload(add(_proof, 1))
	    gammaX := mload(add(_proof, 33))
      c := mload(add(_proof, 49))
      s := mload(add(_proof, 81))
    }
    uint256 gammaY = deriveY(gammaSign, gammaX);

    return [
      gammaX,
      gammaY,
      c,
      s];
  }

  /// @dev Decode EC point from bytes
  /// @param _point The EC point as bytes
  /// @return The point as `[point-x, point-y]`
  function decodePoint(bytes memory _point) internal pure returns (uint[2] memory) {
    require(_point.length == 33, "Malformed compressed EC point");
    uint8 sign;
    uint256 x;
    assembly {
      sign := mload(add(_point, 1))
	    x := mload(add(_point, 33))
    }
    uint256 y = deriveY(sign, x);

    return [x, y];
  }

  /// @dev Compute the parameters (EC points) required for the VRF fast verification function.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @return The fast verify required parameters as the tuple `([uPointX, uPointY], [sHX, sHY, cGammaX, cGammaY])`
  function computeFastVerifyParams(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message)
    internal pure returns (uint256[2] memory, uint256[4] memory)
  {
    // Requirements for Step 3: U = s*B - c*Y (where B is the generator)
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);
    (uint256 uPointX, uint256 uPointY) = ecMulSubMul(
      _proof[3],
      GX,
      GY,
      _proof[2],
      _publicKey[0],
      _publicKey[1]);
    // Requirements for Step 4: V = s*H - c*Gamma
    (uint256 sHX, uint256 sHY) = derivePoint(_proof[3], hPoint[0], hPoint[1]);
    (uint256 cGammaX, uint256 cGammaY) = derivePoint(_proof[2], _proof[0], _proof[1]);

    return (
      [uPointX, uPointY],
      [
        sHX,
        sHY,
        cGammaX,
        cGammaY
      ]);
  }

  /// @dev Function to convert a `Hash(PK|DATA)` to a point in the curve as defined in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04).
  /// Used in Step 2 of VRF verification function.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _message The message used for computing the VRF
  /// @return The hash point in affine cooridnates
  function hashToTryAndIncrement(uint256[2] memory _publicKey, bytes memory _message) internal pure returns (uint, uint) {
    // Step 1: public key to bytes
    // Step 2: V = cipher_suite | 0x01 | public_key_bytes | message | ctr
    bytes memory c = abi.encodePacked(
      // Cipher suite code (SECP256K1-SHA256-TAI is 0xFE)
      uint8(254),
      // 0x01
      uint8(1),
      // Public Key
      encodePoint(_publicKey[0], _publicKey[1]),
      // Message
      _message);

    // Step 3: find a valid EC point
    // Loop over counter ctr starting at 0x00 and do hash
    for (uint8 ctr = 0; ctr < 256; ctr++) {
      // Counter update
      // c[cLength-1] = byte(ctr);
      bytes32 sha = sha256(abi.encodePacked(c, ctr));
      // Step 4: arbitraty string to point and check if it is on curve
      uint hPointX = uint256(sha);
      uint hPointY = deriveY(2, hPointX);
      if (EllipticCurve.isOnCurve(
        hPointX,
        hPointY,
        AA,
        BB,
        PP))
      {
        // Step 5 (omitted): calculate H (cofactor is 1 on secp256k1)
        // If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        return (hPointX, hPointY);
      }
    }
    revert("No valid point was found");
  }

  /// @dev Function to hash a certain set of points as specified in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04).
  /// Used in Step 5 of VRF verification function.
  /// @param _hPointX The coordinate `x` of point `H`
  /// @param _hPointY The coordinate `y` of point `H`
  /// @param _gammaX The coordinate `x` of the point `Gamma`
  /// @param _gammaX The coordinate `y` of the point `Gamma`
  /// @param _uPointX The coordinate `x` of point `U`
  /// @param _uPointY The coordinate `y` of point `U`
  /// @param _vPointX The coordinate `x` of point `V`
  /// @param _vPointY The coordinate `y` of point `V`
  /// @return The first half of the digest of the points using SHA256
  function hashPoints(
    uint256 _hPointX,
    uint256 _hPointY,
    uint256 _gammaX,
    uint256 _gammaY,
    uint256 _uPointX,
    uint256 _uPointY,
    uint256 _vPointX,
    uint256 _vPointY)
  internal pure returns (bytes16)
  {
    bytes memory c = abi.encodePacked(
      // Ciphersuite 0xFE
      uint8(254),
      // Prefix 0x02
      uint8(2),
      // Points to Bytes
      encodePoint(_hPointX, _hPointY),
      encodePoint(_gammaX, _gammaY),
      encodePoint(_uPointX, _uPointY),
      encodePoint(_vPointX, _vPointY)
    );
    // Hash bytes and truncate
    bytes32 sha = sha256(c);
    bytes16 half1;
    assembly {
      let freemem_pointer := mload(0x40)
      mstore(add(freemem_pointer,0x00), sha)
      half1 := mload(add(freemem_pointer,0x00))
    }

    return half1;
  }

  /// @dev Encode an EC point to bytes
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @return The point coordinates as bytes
  function encodePoint(uint256 _x, uint256 _y) internal pure returns (bytes memory) {
    uint8 prefix = uint8(2 + (_y % 2));

    return abi.encodePacked(prefix, _x);
  }

  /// @dev Substracts two key derivation functionsas `s1*A - s2*B`.
  /// @param _scalar1 The scalar `s1`
  /// @param _a1 The `x` coordinate of point `A`
  /// @param _a2 The `y` coordinate of point `A`
  /// @param _scalar2 The scalar `s2`
  /// @param _b1 The `x` coordinate of point `B`
  /// @param _b2 The `y` coordinate of point `B`
  /// @return The derived point in affine cooridnates
  function ecMulSubMul(
    uint256 _scalar1,
    uint256 _a1,
    uint256 _a2,
    uint256 _scalar2,
    uint256 _b1,
    uint256 _b2)
  internal pure returns (uint256, uint256)
  {
    (uint256 m1, uint256 m2) = derivePoint(_scalar1, _a1, _a2);
    (uint256 n1, uint256 n2) = derivePoint(_scalar2, _b1, _b2);
    (uint256 r1, uint256 r2) = EllipticCurve.ecSub(
      m1,
      m2,
      n1,
      n2,
      AA,
      PP);

    return (r1, r2);
  }

  /// @dev Verify an Elliptic Curve multiplication of the form `(qx,qy) = scalar*(x,y)` by using the precompiled `ecrecover` function.
  /// The usage of the precompiled `ecrecover` function decreases the security from 32 to 20 bytes.
  /// Based on the original idea of Vitalik Buterin: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9
  /// @param _scalar The scalar of the point multiplication
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @param _qx The coordinate `x` of the multiplication result
  /// @param _qy The coordinate `y` of the multiplication result
  /// @return true, if first 20 bytes match
  function ecMulVerify(
    uint256 _scalar,
    uint256 _x,
    uint256 _y,
    uint256 _qx,
    uint256 _qy)
  internal pure returns(bool)
  {
    address result = ecrecover(
      0,
      _y % 2 != 0 ? 28 : 27,
      bytes32(_x),
      bytes32(mulmod(_scalar, _x, NN)));

    return pointToAddress(_qx, _qy) == result;
  }

  /// @dev Verify an Elliptic Curve operation of the form `Q = scalar1*(gx,gy) - scalar2*(x,y)` by using the precompiled `ecrecover` function, where `(gx,gy)` is the generator of the EC.
  /// The usage of the precompiled `ecrecover` function decreases the security from 32 to 20 bytes.
  /// Based on SolCrypto library: https://github.com/HarryR/solcrypto
  /// @param _scalar1 The scalar of the multiplication of `(gx,gy)`
  /// @param _scalar2 The scalar of the multiplication of `(x,y)`
  /// @param _x The coordinate `x` of the point to be mutiply by `scalar2`
  /// @param _y The coordinate `y` of the point to be mutiply by `scalar2`
  /// @param _qx The coordinate `x` of the equation result
  /// @param _qy The coordinate `y` of the equation result
  /// @return true, if first 20 bytes match
  function ecMulSubMulVerify(
    uint256 _scalar1,
    uint256 _scalar2,
    uint256 _x,
    uint256 _y,
    uint256 _qx,
    uint256 _qy)
  internal pure returns(bool)
  {
    uint256 scalar1 = (NN - _scalar1) % NN;
    scalar1 = mulmod(scalar1, _x, NN);
    uint256 scalar2 = (NN - _scalar2) % NN;

    address result = ecrecover(
      bytes32(scalar1),
      _y % 2 != 0 ? 28 : 27,
      bytes32(_x),
      bytes32(mulmod(scalar2, _x, NN)));

    return pointToAddress(_qx, _qy) == result;
  }

  /// @dev Gets the address corresponding to the EC point digest (keccak256), i.e. the first 20 bytes of the digest.
  /// This function is used for performing a fast EC multiplication verification.
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @return The address of the EC point digest (keccak256)
  function pointToAddress(uint256 _x, uint256 _y)
      internal pure returns(address)
  {
    return address(uint256(keccak256(abi.encodePacked(_x, _y))) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
  }
}
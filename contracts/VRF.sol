pragma solidity ^0.5.0;

import "./Secp256k1.sol";

/**
 * @title Verifiable Random Functions (VRF)
 * @notice Library for supporting VRF verifications using the curve `Secp256k1` and the hash algorithm `SHA256`.
 * @dev This library follows the algorithms described in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04)
 * and [RFC6979](https://tools.ietf.org/html/rfc6979). It supports the ciphersuite  _SECP256K1_SHA256_TAI_, i.e. the aforementioned algorithms using `SHA256` and the `Secp256k1` curve.
 * @author Witnet Foundation
 */


contract VRF is Secp256k1 {

  /// @dev VRF verification providing the message
  /// @param _publicKey The public key as an array composed of [pubKey-x`, pubKey-y]
  /// @param _proof The VRF proof as an array composed of [gamma-x, gamma-y, c, s]
  /// @param _message The message used for computing the VRF
  /// @return true, if VRF proof is valid
  function verifyMessage(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message) public pure returns (bool) {
    // Step 2: Hash to try and increment
    // Output: hashed value, a finite EC point in G
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);

    return verify(_publicKey, _proof, hPoint);
  }

  /// @dev VRF verification providing the `H` point, thus avoiding Step 2
  /// @param _publicKey The public key as an array composed of [pubKey-x`, pubKey-y]
  /// @param _proof The VRF proof as an array composed of [gamma-x, gamma-y, c, s]
  /// @param _hPoint The pre-computed hash point required to verify the VRF as [hPoint-x, hPoint-y]
  /// @return true, if VRF proof is valid
  function verify(uint256[2] memory _publicKey, uint256[4] memory _proof, uint256[2] memory _hPoint) public pure returns (bool) {
    // Step 3: U = s*B - c*Y (where B is the generator)
    (uint256 uPointX, uint256 uPointY) = sub2Muls(_proof[3], GX, GY, _proof[2], _publicKey[0], _publicKey[1]);
    // Step 4: V = s*H - c*Gamma
    (uint256 vPointX, uint256 vPointY) = sub2Muls(_proof[3], _hPoint[0], _hPoint[1], _proof[2], _proof[0], _proof[1]);
    // Step 5: derived c from hash points(...)
    bytes16 derived_c = hashPoints(_hPoint[0], _hPoint[1], _proof[0], _proof[1], uPointX, uPointY, vPointX, vPointY);
    // Step 6: Check validity c == c'
    return uint128(derived_c) == _proof[2];
  }

  /// @dev Substracts two key derivation functions, i.e. two multiplications of an scalar times a point
  /// @param _s1 The scalar `s1`
  /// @param _a1 The `x` coordinate of point `A`
  /// @param _a2 The `y` coordinate of point `A`
  /// @param _s2 The scalar `s2`
  /// @param _b1 The `x` coordinate of point `B`
  /// @param _b2 The `y` coordinate of point `B`
  /// @return The derived point in affine cooridnates
  function sub2Muls(uint256 _s1, uint256 _a1, uint256 _a2, uint256 _s2, uint256 _b1, uint256 _b2) internal pure returns (uint256, uint256) {
    (uint256 m1, uint256 m2) = derivePoint(_s1, _a1, _a2);
    (uint256 n1, uint256 n2) = derivePoint(_s2, _b1, _b2);
    (uint256 r1, uint256 r2) = ecSub(m1, m2, n1, n2, AA, PP);

    return (r1, r2);
  }

  /// @dev Function to convert a `Hash(PK|DATA)` to a point in the curve as stated in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04)
  /// @param _publicKey The public key as an array composed of [pubKey-x`, pubKey-y]
  /// @param _message The message used for computing the VRF
  /// @return The hash point in affine cooridnates
  function hashToTryAndIncrement(uint256[2] memory _publicKey, bytes memory _message) public pure returns (uint, uint) {
    // Prepare bytes
    uint cLength = 2 + 33 + _message.length + 1;
    bytes memory c = new bytes(cLength);
    // Step 1: public key to bytes
    bytes memory pkBytes = encodePoint(_publicKey[0], _publicKey[1]);
    // Step 2: V = cipher_suite | 0x01 | public_key_bytes | message | ctr
    // Ciphersuite code for SECP256K1-SHA256-TAI is 0xFE
    c[0] = byte(uint8(254));
    c[1] = byte(uint8(1));
    for (uint i = 0; i < pkBytes.length; i++) {
      c[2+i] = pkBytes[i];
    }
    for (uint i = 0; i < _message.length; i++) {
      c[35+i] = _message[i];
    }
    // Step 3: find a valid EC point
    // loop over counter ctr starting at 0x00 and do hash
    for (uint8 ctr = 0; ctr < 256; ctr++) {
      // Counter update
      c[cLength-1] = byte(ctr);
      bytes32 sha = sha256(c);
      // Step 4: arbitraty string to point and check if it is on curve
      uint hPointX = uint256(sha);
      uint hPointY = deriveY(2, hPointX);
      if (isOnCurve(hPointX, hPointY, AA, BB, PP)) {
        // Step 5 (omitted): calculate H (cofactor is 1 on secp256k1)
        // If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        return (hPointX, hPointY);
      }
    }
    revert("No valid point was found");
  }

  /// @dev Function to hash a certain set of points as specified in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04)
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
  public pure returns (bytes16) {
    bytes memory c = new bytes(134);
    // Ciphersuite 0xFE
    c[0] = byte(uint8(254));
    // Prefix 0x02
    c[1] = byte(uint8(2));
    // Points to Bytes
    bytes memory hBytes = encodePoint(_hPointX, _hPointY);
    for (uint i = 0; i < hBytes.length; i++) {
      c[2+i] = hBytes[i];
    }
    bytes memory gammaBytes = encodePoint(_gammaX, _gammaY);
    for (uint i = 0; i < gammaBytes.length; i++) {
      c[35+i] = gammaBytes[i];
    }
    bytes memory uBytes = encodePoint(_uPointX, _uPointY);
    for (uint i = 0; i < uBytes.length; i++) {
      c[68+i] = uBytes[i];
    }
    bytes memory vBytes = encodePoint(_vPointX, _vPointY);
    for (uint i = 0; i < vBytes.length; i++) {
      c[101+i] = vBytes[i];
    }
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

  /// @dev Function to derive the `y` coordinate given the `x` coordinate and the parity byte
  /// @param _yBit The parity byte following the ec point compressed format
  /// @param _x The coordinate `x` of the point
  /// @return The coordinate `y` of the point
  function deriveY(uint8 _yBit, uint256 _x) public pure returns (uint256) {
    uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, PP), PP), 7, PP);
    uint256 y = expMod(y2, (PP + 1) / 4, PP);
    y = (y + _yBit) % 2 == 0 ? y : PP - y;

    return y;
  }

  /// @dev Decode from bytes a VRF proof
  /// @param _proof The VRF proof as an array composed of [gamma-x, gamma-y, c, s]
  /// @return The VRF proof as an array composed of [gamma-x, gamma-y, c, s]
  function decodeProof(bytes memory _proof) public pure returns (uint[4] memory) {

    uint8 gamma_sign;
    uint256 gamma_x;
    uint128 c;
    uint256 s;
    assembly {
      gamma_sign := mload(add(_proof, 1))
	    gamma_x := mload(add(_proof, 33))
      c := mload(add(_proof, 49))
      s := mload(add(_proof, 81))
    }
    uint256 gamma_y = deriveY(gamma_sign, gamma_x);

    return [gamma_x, gamma_y, c, s];
  }

  /// @dev Decode from bytes an EC point
  /// @param _point The EC point as bytes
  /// @return The point as [point-x, point-y]
  function decodePoint(bytes memory _point) public pure returns (uint[2] memory) {
    uint8 sign;
    uint256 x;
    assembly {
      sign := mload(add(_point, 1))
	    x := mload(add(_point, 33))
    }
    uint256 y = deriveY(sign, x);

    return [x, y];
  }

  /// @dev Encode an EC point to bytes
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @return The point coordinates as bytes
  function encodePoint(uint256 _x, uint256 _y) public pure returns (bytes memory) {
    uint8 prefix = uint8(2 + (_y % 2));
    bytes memory pb1 = new bytes(1);
    pb1[0] = byte(prefix);
    bytes memory pb2 = new bytes(32);
    assembly {
      mstore(add(pb2, 32), _x)
    }

    return mergeBytes(pb1, pb2);
  }

  /// @dev Merge two bytes structures into one
  /// @param _a The bytes `a`
  /// @param _b The bytes `b`
  /// @return The merged bytes
  function mergeBytes(bytes memory _a, bytes memory _b) public pure returns (bytes memory) {
    uint totallen = _a.length + _b.length;
    bytes memory c = new bytes(totallen);
    for (uint i = 0; i < _a.length; i++) {
      c[i] = _a[i];
    }
    for (uint j = 0; j < _b.length; j++) {
      c[_a.length+j] = _b[j];
    }

    return c;
  }
}
pragma solidity ^0.5.0;

import "./EllipticCurve.sol";

contract VRF is EllipticCurve {

  uint256 constant gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint256 constant gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  uint256 constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  function decode_proof(bytes memory proof) public pure returns (uint[4] memory) {

    uint8 gamma_sign;
    uint256 gamma_x;
    uint128 c;
    uint256 s;

    assembly {
      gamma_sign := mload(add(proof, 1))
	    gamma_x := mload(add(proof, 33))
      c := mload(add(proof, 49))
      s := mload(add(proof, 81))
    }

    uint256 gamma_y = derive_y(gamma_sign, gamma_x);

    return [gamma_x, gamma_y, c, s];
  }

  function decode_point(bytes memory proof) public pure returns (uint[2] memory) {
    uint8 sign;
    uint256 x;

    assembly {
      sign := mload(add(proof, 1))
	    x := mload(add(proof, 33))
    }
    uint256 y = derive_y(sign, x);

    return [x, y];
  }

  function encode_point(uint256 x, uint256 y) public pure returns (bytes memory) {
    uint8 prefix = uint8(2 + (y % 2));
    bytes memory pb1 = new bytes(1);
    pb1[0] = byte(prefix);
    bytes memory pb2 = uint256ToBytes(x);

    return mergeBytes(pb1, pb2);
  }

  function verify_with_message(uint256[2] memory publicKey, uint256[4] memory proof, bytes memory message) public pure returns (bool) {
    uint[2] memory h_point;
    (h_point[0], h_point[1]) = hashToTryAndIncrement(publicKey, message);

    return verify(publicKey, proof, h_point);
  }

  function verify(uint256[2] memory publicKey, uint256[4] memory proof, uint256[2] memory h_point) public pure returns (bool) {

    // // uint256 gamma_x = proof[0];
    // // uint256 gamma_y = proof[1]; // no sirve!
    // // uint256 c = proof[2];
    // // uint256 s = proof[3];
    // // uint256 h_x = h_point[0];
    // // uint256 h_y = h_point[1];

    // // Step 2: Hash to try and increment
    // // Output: hashed value, a finite EC point in G
    // // (uint256 h_x, uint256 h_y) = _hashToTryAndIncrement(publicX, publicY, message);

    // // Step 3: U = s*B - c*Y (where B is the generator)
    (uint256 u_x, uint256 u_y) = sub2Muls(proof[3], gx, gy, proof[2], publicKey[0], publicKey[1]);

    // // Step 4: V = s*H - c*Gamma
    (uint256 v_x, uint256 v_y) = sub2Muls(proof[3], h_point[0], h_point[1], proof[2], proof[0], proof[1]);

    // Step 5: derived c from hash points(...)
    bytes16 derived_c = hash_points(h_point[0], h_point[1], proof[0], proof[1], u_x, u_y, v_x, v_y);

    // Step 6: Check validity c == c'
    return uint128(derived_c) == proof[2];
  }

  // result = s1*A - s2*B
  function sub2Muls(uint256 s1, uint256 a1, uint256 a2, uint256 s2, uint256 b1, uint256 b2) internal pure returns (uint256, uint256) {
    (uint256 m1, uint256 m2) = deriveKey(s1, a1, a2);
    (uint256 n1, uint256 n2) = deriveKey(s2, b1, b2);
    (uint256 r1, uint256 r2) = sub(m1, m2, n1, n2);

    return (r1, r2);
  }

  //TODO: to review
  /// @dev See Curve.derive_y
  function derive_y(uint8 yBit, uint256 x) public pure returns (uint256 y) {
    uint256 p = pp;
    uint256 y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
    uint256 y_ = _expMod(y2, (p + 1) / 4, p);
    // uint256 cmp = yBit ^ y_ & 1;
    y = (y_ + yBit) % 2 == 0 ? y_ : p - y_;
  }

  function hash_points(uint256 h_x, uint256 h_y, uint256 gamma_x, uint256 gamma_y, uint256 u_x, uint256 u_y, uint256 v_x, uint256 v_y)
  public pure returns (bytes16) {
    bytes memory c = new bytes(134);
    // Ciphersuite 0xFE
    c[0] = byte(uint8(254));
    // Prefix 0x02
    c[1] = byte(uint8(2));
    // Points to Bytes
    bytes memory hBytes = encode_point(h_x, h_y);
    for (uint i = 0; i < hBytes.length; i++) {
      c[2+i] = hBytes[i];
    }
    bytes memory gammaBytes = encode_point(gamma_x, gamma_y);
    for (uint i = 0; i < gammaBytes.length; i++) {
      c[35+i] = gammaBytes[i];
    }
    bytes memory uBytes = encode_point(u_x, u_y);
    for (uint i = 0; i < uBytes.length; i++) {
      c[68+i] = uBytes[i];
    }
    bytes memory vBytes = encode_point(v_x, v_y);
    for (uint i = 0; i < vBytes.length; i++) {
      c[101+i] = vBytes[i];
    }

    // Hash bytes and truncate
    bytes32 sha = sha256(c);
    bytes16 half1;
    bytes16 half2;
    assembly {
      let freemem_pointer := mload(0x40)
      mstore(add(freemem_pointer,0x00), sha)
      half1 := mload(add(freemem_pointer,0x00))
      half2 := mload(add(freemem_pointer,0x10))
    }

    return half1;
  }

  function mergeBytes(bytes memory a, bytes memory b) public pure returns (bytes memory) {
    uint totallen = a.length + b.length;
    bytes memory c = new bytes(totallen);
    for (uint i = 0; i < a.length; i++) {
      c[i] = a[i];
    }
    for (uint j = 0; j < b.length; j++) {
      c[a.length+j] = b[j];
    }

    return c;
  }

  function uint256ToBytes(uint256 x) public pure returns (bytes memory b) {
    b = new bytes(32);
    assembly {
      mstore(add(b, 32), x)
    }
  }

  function hashToTryAndIncrement(uint256[2] memory public_key, bytes memory message) public pure returns (uint, uint) {
    // Prepare bytes
    uint v_length = 2 + 33 + message.length + 1;
    bytes memory c = new bytes(v_length);
    uint8 ctr = 0;

    // Step 1: public key to bytes
    bytes memory pkBytes = encode_point(public_key[0], public_key[1]);

    // Step 2: V = cipher_suite | 0x01 | public_key_bytes | message | ctr
    // Ciphersuite 0xFE
    c[0] = byte(uint8(254));
    // Prefix 0x02
    c[1] = byte(uint8(1));
    // Public Key
    for (uint i = 0; i < pkBytes.length; i++) {
      c[2+i] = pkBytes[i];
    }
    // Message
    for (uint i = 0; i < message.length; i++) {
      c[35+i] = message[i];
    }
    // Counter
    c[v_length-1] = byte(ctr);

    // Step 3: find a valid EC point
    // loop over counter ctr starting at 0x00 and do hash
    bytes32 sha = sha256(c);

    // Step 4: arbitraty string to point
    uint h_x = uint256(sha);
    uint h_y = derive_y(2, h_x);

    // Step 5: calculate H
    // If H is not "INVALID" and cofactor > 1, set H = cofactor * H

    return (h_x, h_y);
  }

}
pragma solidity ^0.5.0;

import "./EllipticCurve.sol";

contract VRF is EllipticCurve {

  uint256 constant gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint256 constant gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  uint256 constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  // function decode_proof(bytes memory proof) public pure returns (uint256) {
  //   uint8 gamma_sign;
  //   uint256 gamma_x;
  //   // uint256 gamma_y; // no sirve!
  //   uint256 c;
  //   // uint256 s;

  //   assembly {
  //     gamma_sign := mload(add(proof, 1))
	//     gamma_x := mload(add(proof, 33))
  //     c := mload(add(proof, 78))
  //     // s := mload(add(proof, 110))
  //   }

  //   return gamma_x;
  // }

  function verify(uint256[2] memory publicKey, uint256[4] memory proof, bytes memory message, uint256[2] memory h_point) public pure returns (bool) {

    // // uint256 gamma_x = proof[0];
    // // uint256 gamma_y = proof[1]; // no sirve!
    // // uint256 c = proof[2];
    // // uint256 s = proof[3];
    // // uint256 h_x = h_point[0];
    // // uint256 h_y = h_point[1];

    // // Step 2: Hash to try and increment
    // // Output: hashed value, a finite EC point in G
    // // (uint256 h_x, uint256 h_y) = _hashToTryAndIncrement(gamma_x, gamma_y, message);

    // // Step 3: U = s*B - c*Y (where B is the generator)
    // (uint256 sB_x, uint256 sB_y) = derivePublicKey(proof[3]);
    // (uint256 cY_x, uint256 cY_y) = deriveKey(proof[2], publicKey[0], publicKey[1]);
    // (uint256 u_x, uint256 u_y) = _jSub(sB_x, sB_y, cY_x, cY_y);
    (uint256 u_x, uint256 u_y) = sub2Muls(proof[3], gx, gy, proof[2], publicKey[0], publicKey[1]);

    // // Step 4: V = s*H - c*Gamma
    // (uint256 sH_x, uint256 sH_y) = deriveKey(proof[3], h_point[0], h_point[1]);
    // (uint256 cG_x, uint256 cG_y) = deriveKey(proof[2], proof[0], proof[1]);

    // uint256 mcG_y = _inverse(cG_y);
    // (uint256 v_x, uint256 v_y) = _jSub(sH_x, sH_y, cG_x, cG_y);
    (uint256 v_x, uint256 v_y) = sub2Muls(proof[3], h_point[0], h_point[1], proof[2], proof[0], proof[1]);


    // Step 5: derived c from hash points(...)
    //let derived_c = self.hash_points(&[&h_point, &gamma_point, &u_point, &v_point])?;
    bytes16 derived_c = hash_points(h_point[0], h_point[1], proof[0], proof[1], u_x, u_y, v_x, v_y);

    // // Step 6: Check validity c == c'
    // uint256 dc;
    // assembly {
    //     dc := mload(add(derived_c, 0x20))
    // }

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
  /// @dev See Curve.decompress
  function decompress(uint8 yBit, uint256 x) public pure returns (uint256[2] memory P) {
    uint256 p = pp;
    uint256 y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
    uint256 y_ = expmod(y2, (p + 1) / 4, p);
    // uint256 cmp = yBit ^ y_ & 1;
    P[0] = x;
    P[1] = (y_ + yBit) % 2 == 0 ? y_ : p - y_;
  }

  function hash_points(uint256 h_x, uint256 h_y, uint256 gamma_x, uint256 gamma_y, uint256 u_x, uint256 u_y, uint256 v_x, uint256 v_y)
  public pure returns (bytes16) {
    bytes memory c = new bytes(134);
    // Ciphersuite 0xFE
    c[0] = byte(uint8(254));
    // Prefix 0x02
    c[1] = byte(uint8(2));
    // Points to Bytes
    bytes memory hBytes = point_to_bytes(h_x, h_y);
    for (uint i = 0; i < hBytes.length; i++) {
      c[2+i] = hBytes[i];
    }
    bytes memory gammaBytes = point_to_bytes(gamma_x, gamma_y);
    for (uint i = 0; i < gammaBytes.length; i++) {
      c[35+i] = gammaBytes[i];
    }
    bytes memory uBytes = point_to_bytes(u_x, u_y);
    for (uint i = 0; i < uBytes.length; i++) {
      c[68+i] = uBytes[i];
    }
    bytes memory vBytes = point_to_bytes(v_x, v_y);
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

  function point_to_bytes (uint256 x, uint256 y) public pure returns (bytes memory) {
    uint8 prefix = uint8(2 + (y % 2));
    bytes memory pb1 = new bytes(1);
    pb1[0] = byte(prefix);
    bytes memory pb2 = uint256ToBytes(x);

    return mergeBytes(pb1, pb2);
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

  // function _hashToTryAndIncrement (uint256 pk_x, uint256 pk_y, bytes memory message) public pure returns (uint256 h_x, uint256 h_y) {
  //   // Step 1: public key to bytes
  //   // 04+X+Y as uncompressed
  //   // (02+X as compressed if Y is even)
  //   // (03+X as compressed if Y is odd)
  //   // Step 2: V = cipher_suite | 0x01 | public_key_bytes | message | ctr
  //   // Step 3: find a valid EC point
  //   // loop over counter ctr starting at 0x00 and do hash
  //   // hash = sha256(V | ctr)
  //   // Step 4: arbitraty string to point
  //   // Step 5: calculate H
  //   // If H is not "INVALID" and cofactor > 1, set H = cofactor * H
  // }

  // function _arbitratyStringToPoint (uint256 data) public pure returns (uint256 p_x, uint256 p_y) {
  //   // Appending 0x02 is not neccesary as it will be assumed that it is compressed
  //   // Create ECPoint from bytes
  //   // beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
  // }

}
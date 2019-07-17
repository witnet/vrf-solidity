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
  // Constans for scalar decomposition. Source: https://github.com/mimblewimble/secp256k1-zkp/blob/master/src/scalar_impl.h
  uint256 constant MINUSLAMBDA= 0xAC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CF;
  uint256 constant MINUSB1 = 0x00000000000000000000000000000000E4437ED6010E88286F547FA90ABFE4C3;
  uint256 constant MINUSB2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C;
  uint256 constant G1 = 0x00000000000000000000000000003086D221A7D46BCDE86C90E49284EB153DAB;
  uint256 constant G2 = 0x0000000000000000000000000000E4437ED6010E88286F547FA90ABFE4C42212;
  uint256 constant BETA = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee;


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

  /// @dev Function to derive the `y` coordinate given the `x` coordinate and the parity byte.
  /// @param _yBit The parity byte following the ec point compressed format
  /// @param _x The coordinate `x` of the point
  /// @return The coordinate `y` of the point
  function deriveY(uint8 _yBit, uint256 _x) public pure returns (uint256) {
    uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, PP), PP), 7, PP);
    uint256 y = expMod(y2, (PP + 1) / 4, PP);
    y = (y + _yBit) % 2 == 0 ? y : PP - y;

    return y;
  }

  /// @dev Perform 256 times 256 multiplication (Source: https://github.com/gnosis/solidity-arithmetic/blob/master/contracts/Arithmetic.sol)
  /// @param a uint256 representing first multiplicant
  /// @param b uint256 representing second multiplicant
  /// @return (uint256, uint128, uint128) the multiplication represented in limbs
  function mul256By256(uint a, uint b)
        internal pure
        returns (uint ab32, uint ab1, uint ab0)
  {
    uint ahi = a >> 128;
    uint alo = a & 2**128-1;
    uint bhi = b >> 128;
    uint blo = b & 2**128-1;
    ab0 = alo * blo;
    ab1 = (ab0 >> 128) + (ahi * blo & 2**128-1) + (alo * bhi & 2**128-1);
    ab32 = (ab1 >> 128) + ahi * bhi + (ahi * blo >> 128) + (alo * bhi >> 128);
    ab1 &= 2**128-1;
    ab0 &= 2**128-1;
  }

  /// @dev Perform scalar decomposition. Inspired by https://github.com/mimblewimble/secp256k1-zkp/blob/master/src/scalar_impl.h
  /// @param num A 256-bit integer
  /// @return (uint256, uint256) respresenting the splitted version of num
  function roundedsplitDiv(uint256 num) internal pure returns(uint256 r1, uint256 r2) {
    uint256 c1;
    uint256 c2;
    uint256 t1;
    uint256 t2;
    uint t3;
    (t1, t2, t3) = mul256By256(num, G1);
    c1 = fromUInt(t1 >> 16);
    (t1, t2, t3) = mul256By256(num, G2);
    c2 = fromUInt(t1 >> 16);

    c1 = mulmod(c1, MINUSB1, NN);
    c2 = mulmod(c2, MINUSB2, NN);

    r2 = addmod(c1, c2, NN);
    r1 = mulmod(r2, MINUSLAMBDA, NN);
    r1 = addmod(r1, num, NN);

    return(r1,r2);
  }

  /// @dev Return a rounded uint128 from uint256 representing a float. Inspired by: https://github.com/abdk-consulting/abdk-libraries-solidity/blob/master/ABDKMathQuad.sol
  /// @param x A 256-bit integer
  /// @return (uint128) respresenting the rounded integer
  function fromUInt (uint256 x) internal pure returns (uint128) {
    if (x == 0)
      return (0);
    else {
      uint256 result = x;

      uint256 msb = msb (result);
      result = result + (0x01 << (msb-53));

      result = result & (0xFFFFFFFFFFFFFF << (msb-52));

      return uint128 (result);
    }
  }

  /// @notice Computes the WNAF representation of an integer, and puts the resulting array of coefficients in memory. Source: https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
  /// @param d A 256-bit integer
  /// @return (ptr, length) The pointer to the first coefficient, and the total length of the array
  function _wnaf(int256 d) internal pure  returns (uint256 ptr, uint256 length) {
    int sign = d < 0 ? -1 : int(1);
    uint256 k = uint256(sign * d);

    length = 0;
    assembly
    {
      let ki := 0
      ptr := mload(0x40) // Get free memory pointer
      mstore(0x40, add(ptr, 300)) // Updates free memory pointer to +300 bytes offset
      for { } gt(k, 0) { } { // while k > 0
        if and(k, 1) {  // if k is odd:
          ki := mod(k, 16)
          k := add(sub(k, ki), mul(gt(ki, 8), 16))
          // if sign = 1, store ki; if sign = -1, store 16 - ki
          mstore8(add(ptr, length), add(mul(ki, sign), sub(8, mul(sign, 8))))
        }
        length := add(length, 1)
        k := div(k, 2)
      }
    }

    return (ptr, length);
  }

  /// @notice Simultaneous multiplication of the form kP + lQ. Source: https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
  /// @dev Scalars k and l are expected to be decomposed such that k = k1 + k2 λ, and l = l1 + l2 λ,
  /// where λ is specific to the endomorphism of the curve
  /// @param k_l An array with the decomposition of k and l values, i.e., [k1, k2, l1, l2]
  /// @param P_Q An array with the affine coordinates of both P and Q, i.e., [P1, P2, Q1, Q2]
  function simMul(int256[4] memory k_l, uint256[4] memory P_Q) internal pure returns (uint[3] memory Q) {

    require(
      isOnCurve(
        P_Q[0],
        P_Q[1],
        AA,
        BB,
        PP) &&
      isOnCurve(
        P_Q[2],
        P_Q[3],
        AA,
        BB,
        PP),
    "Invalid points"
    );

    uint256[4] memory wnaf;
    uint256 max_count = 0;
    uint256 count = 0;

    for (uint j = 0; j<4; j++) {
      (wnaf[j], count) = _wnaf(k_l[j]);
      if (count > max_count) {
        max_count = count;
      }
    }

    Q = simMulWnaf(wnaf, max_count, P_Q);
  }

  /// @notice Simultaneous multiplication given wnaf scalars and 2 points kP + lQ. Source: https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
  /// @dev Scalars k and l are expected to be decomposed such that k = k1 + k2 λ, and l = l1 + l2 λ,
  /// where λ is specific to the endomorphism of the curve
  /// @param _wnafPtr WNAF representation of decomposed scalars
  /// @param _length length of the wnaf pointer
  /// @param P_Q An array with the affine coordinates of both P and Q, i.e., [P1, P2, Q1, Q2]
  function simMulWnaf(uint256[4] memory _wnafPtr, uint256 _length, uint256[4] memory P_Q) internal pure returns (uint[3] memory Q) {
    uint256[3][4][4] memory iP;
    lookupSimMul(iP, P_Q);

    uint256 i = _length;
    uint256 ki;
    uint256 ptr;
    while (i > 0) {
      i--;

      (Q[0], Q[1], Q[2]) = jacDouble(
        Q[0],
        Q[1],
        Q[2],
        AA,
        PP);

      ptr = _wnafPtr[0] + i;
      assembly {
        ki := byte(0, mload(ptr))
      }

      if (ki > 8) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[0][(15 - ki) / 2][0],
          (PP - iP[0][(15 - ki) / 2][1]) % PP,
          iP[0][(15 - ki) / 2][2],
          PP);
      } else if (ki > 0) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[0][(ki - 1) / 2][0],
          iP[0][(ki - 1) / 2][1],
          iP[0][(ki - 1) / 2][2],
          PP);
      }

      ptr = _wnafPtr[1] + i;
      assembly {
        ki := byte(0, mload(ptr))
      }

      if (ki > 8) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[1][(15 - ki) / 2][0],
          (PP - iP[1][(15 - ki) / 2][1]) % PP,
          iP[1][(15 - ki) / 2][2],
          PP);

      } else if (ki > 0) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[1][(ki - 1) / 2][0],
          iP[1][(ki - 1) / 2][1],
          iP[1][(ki - 1) / 2][2],
          PP);
      }

      ptr = _wnafPtr[2] + i;
      assembly {
        ki := byte(0, mload(ptr))
      }

      if (ki > 8) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[2][(15 - ki) / 2][0],
          (PP - iP[2][(15 - ki) / 2][1]) % PP,
          iP[2][(15 - ki) / 2][2],
          PP);
      } else if (ki > 0) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[2][(ki - 1) / 2][0],
          iP[2][(ki - 1) / 2][1],
          iP[2][(ki - 1) / 2][2],
          PP);
      }

      ptr = _wnafPtr[3] + i;
      assembly {
        ki := byte(0, mload(ptr))
      }

      if (ki > 8) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[3][(15 - ki) / 2][0],
          (PP - iP[3][(15 - ki) / 2][1]) % PP,
          iP[3][(15 - ki) / 2][2], PP);
      } else if (ki > 0) {
        (Q[0], Q[1], Q[2]) = jacAdd(
          Q[0],
          Q[1],
          Q[2],
          iP[3][(ki - 1) / 2][0],
          iP[3][(ki - 1) / 2][1],
          iP[3][(ki - 1) / 2][2],
          PP);
      }
    }
  }

  /// @notice Builds necessary lookup tables for multiplication. Source: https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
  /// @dev Pre-computes 3P, 5P, 7P to faster compute multiplication
  /// @param iP multi-dimensional array where look-up tables will be stored
  /// @param P_Q An array with the affine coordinates of both P and Q, i.e., [P1, P2, Q1, Q2]
  function lookupSimMul(uint256[3][4][4] memory iP, uint256[4] memory P_Q) internal pure {

    uint256 p = PP;
    uint256[3][4] memory iPj;
    uint256[3] memory double;

    // P1 Lookup Table
    iPj = iP[0];
    iPj[0] = [P_Q[0], P_Q[1], 1];  						// P1

    (double[0], double[1], double[2]) = jacDouble(
      iPj[0][0],
      iPj[0][1],
      1,
      AA,
      PP);
    (iPj[1][0], iPj[1][1], iPj[1][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[0][0],
      iPj[0][1],
      iPj[0][2],
      PP);
    (iPj[2][0], iPj[2][1], iPj[2][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[1][0],
      iPj[1][1],
      iPj[1][2],
      PP);
    (iPj[3][0], iPj[3][1], iPj[3][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[2][0],
      iPj[2][1],
      iPj[2][2],
      PP);

    // P2 Lookup Table
    iP[1][0] = [mulmod(BETA, P_Q[0], p), P_Q[1], 1];	// P2

    iP[1][1] = [mulmod(BETA, iPj[1][0], p), iPj[1][1], iPj[1][2]];
    iP[1][2] = [mulmod(BETA, iPj[2][0], p), iPj[2][1], iPj[2][2]];
    iP[1][3] = [mulmod(BETA, iPj[3][0], p), iPj[3][1], iPj[3][2]];

    // Q1 Lookup Table
    iPj = iP[2];
    iPj[0] = [P_Q[2], P_Q[3], 1];
    (double[0], double[1], double[2]) = jacDouble(
      iPj[0][0],
      iPj[0][1],
      1,
      AA,
      PP);
    (iPj[1][0], iPj[1][1], iPj[1][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[0][0],
      iPj[0][1],
      iPj[0][2],
      PP);
    (iPj[2][0], iPj[2][1], iPj[2][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[1][0],
      iPj[1][1],
      iPj[1][2],
      PP);
    (iPj[3][0], iPj[3][1], iPj[3][2]) = jacAdd(
      double[0],
      double[1],
      double[2],
      iPj[2][0],
      iPj[2][1],
      iPj[2][2],
      PP);

    // Q2 Lookup Table
    iP[3][0] = [mulmod(BETA, P_Q[2], p), P_Q[3], 1];	// P2

    iP[3][1] = [mulmod(BETA, iPj[1][0], p), iPj[1][1], iPj[1][2]];
    iP[3][2] = [mulmod(BETA, iPj[2][0], p), iPj[2][1], iPj[2][2]];
    iP[3][3] = [mulmod(BETA, iPj[3][0], p), iPj[3][1], iPj[3][2]];
  }

  /// @dev Returns the index of the most significant non-zero bit of x. Source: https://github.com/abdk-consulting/abdk-libraries-solidity/blob/master/ABDKMathQuad.sol
  /// @param x A 256-bit integer
  /// @return (uint256) respresenting the index of the msb
  function msb (uint256 x) private pure returns (uint256) {
    require (x > 0, "Input number bigger than 0");

    uint256 a = 0;
    uint256 b = 255;
    while (a < b) {
      uint256 m = a + b >> 1;
      uint256 t = x >> m;
      if (t == 0)
        b = m - 1;
      else if (t > 1)
        a = m + 1;
      else {
        a = m;
        break;
      }
    }

    return a;
  }
}
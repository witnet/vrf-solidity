# vrf-solidity [![npm version](https://badge.fury.io/js/vrf-solidity.svg)](https://badge.fury.io/js/vrf-solidity) [![TravisCI](https://travis-ci.com/witnet/vrf-solidity.svg?branch=master)](https://travis-ci.com/witnet/vrf-solidity)

`vrf-solidity` is an open source fast and effective implementation of Verifiable Random Functions (VRFs) written in Solidity. More precisely, this library implements verification functions for VRF proofs based on the Elliptic Curve (EC) `Secp256k1`.

_DISCLAIMER: This is experimental software. **Use it at your own risk**!_

The solidity library has been designed aiming at decreasing gas consumption and its complexity due to EC operations.

It provides two main `pure` functions for verifying VRF proofs:

- **verify**:
  - _Description_: VRF *full* verification (requires heavy EC computation)
  - _Inputs_:
    - *_publicKey*: The public key as an array composed of `[pubKey-x, pubKey-y]`
    - *_proof*: The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
    - *_message*: The message (in bytes) used for computing the VRF
  - _Output_:
    - true, if VRF proof is valid
- **fastVerify**:
  - _Description_: VRF *fast* verification by providing additional EC points. It uses the `ecrecover` precompiled function to verify EC multiplications (lower gas consumption).
  - _Inputs_:
    - *_publicKey*: The public key as an array composed of `[pubKey-x, pubKey-y]`
    - *_proof*: The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
    - *_message*: The message (in bytes) used for computing the VRF
    - *_uPoint*: The `u` EC point defined as `U = s*B - c*Y`
    - *_vComponents*: The components required to compute `v` as `V = s*H - c*Gamma`
  - _Output_:
    - true, if VRF proof is valid

Additionally, the library provides some auxiliary `pure` functions to facilitate computing the aforementioned input parameters:

- **decodeProof**:
  - _Description_: Decode from bytes to VRF proof
  - _Input_:
    - *_proof*: The VRF proof as bytes
  - _Output_:
    - The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
- **decodePoint**:
  - _Description_: Decode from bytes to EC point
  - _Input_:
    - *_point*: The EC point as bytes
  - _Output_:
    - The point as `[point-x, point-y]`
- **computeFastVerifyParams**:
  - _Description_: Compute the parameters (EC points) required for the VRF fast verification function
  - _Inputs_:
    - *_publicKey*: The public key as an array composed of `[pubKey-x, pubKey-y]`
    - *_proof*: The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
    - *_message*: The message (in bytes) used for computing the VRF
  - _Output_:
    - The fast verify required parameters as the tuple `([uPointX, uPointY], [sHX, sHY, cGammaX, cGammaY])`
- **gammaToHash**:
  - _Description_: Computes the VRF hash output as result of the digest of a ciphersuite-dependent prefix concatenated with the gamma point. This hash can be used for deterministically generating verifiable pseudorandom numbers.
  - _Inputs_:
    - *_gammaX*: The x-coordinate of the gamma EC point
    - *_gammaY*: The y-coordinate of the gamma EC point
  - _Output_:
    - The VRF hash ouput as shas256 digest

## Elliptic Curve VRF (using `Secp256k1`)

This library follows the algorithms described in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04) in order to provide the VRF verification capability.

The supported cipher suite is `SECP256K1_SHA256_TAI`, i.e. the aforementioned algorithms using `SHA256` as digest function and the `secp256k1` curve. For the VRF algorithms the cipher suite code used is `0xFE`.

For elliptic curve arithmetic operations `vrf-solidity` uses the `elliptic-curve-solidity` library.

## Usage

`VRF.sol` library can be used directly by importing it.

Similarly to the [`VRFTestHelper.sol`](https://github.com/witnet/vrf-solidity/blob/master/test/VRFTestHelper.sol) from the [`test`][test-folder] project folder, a contract may use the library by instantiation as follows:

```solidity
pragma solidity 0.6.12;

import "vrf-solidity/contracts/VRF.sol";


contract VRFTestHelper {

  function functionUsingVRF(
    uint256[2] memory public _publicKey,
    uint256[4] memory public _proof,
    bytes memory _message)
  public returns (bool)
  {
    return VRF.verify(_publicKey, _proof, _message);
  }
}
```

The tests under the [`test`][test-folder] folder can be seen as additional examples for interacting with the contract using Solidity and Javascript.

## Benchmark

Gas consumption analysis was conducted in order  to understand the associated costs to the usage of the `vrf-solidity` library. Only `public` functions were object of study as they are the only functions meant to be called by other parties.

The three auxiliary public functions (`decodeProof`, `decodePoint` and `computeFastVerifyParams`) are recommended to be used (if possible) as off-chain operations, so that there is not gas costs.

Gas consumption and USD price estimation with a gas price of 20 Gwei, derived from [ETH Gas Station](https://ethgasstation.info/):

```
·············································|···························|·············|·····························
|  Methods                                   ·               20 gwei/gas               ·       176.87 usd/eth       │
·················|···························|·············|·············|·············|··············|··············
|  Contract      ·  Method                   ·  Min        ·  Max        ·  Avg        ·  # calls     ·  usd (avg)  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  computeFastVerifyParams  ·    1732663  ·    2056541  ·    1835085  ·          91  ·       6.49  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  decodePoint              ·      57872  ·      57905  ·      57895  ·          10  ·       0.20  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  decodeProof              ·      61316  ·      61380  ·      61354  ·          10  ·       0.22  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  fastVerify               ·     126323  ·     372749  ·     170598  ·          94  ·       0.60  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  gammaToHash              ·      27685  ·      27749  ·      27732  ·          91  ·       0.10  │
·················|···························|·············|·············|·············|··············|··············
|  VRFGasHelper  ·  verify                   ·    1763117  ·    2087745  ·    1866877  ·          92  ·       6.60  │
·················|···························|·············|·············|·············|··············|··············
|  Deployments                               ·                                         ·  % of limit  ·             │
·············································|·············|·············|·············|··············|··············
|  VRFGasHelper                              ·          -  ·          -  ·    2014186  ·        30 %  ·       7.13  │
·--------------------------------------------|-------------|-------------|-------------|--------------|-------------·
```

## Test Vectors

The following resources have been used for test vectors:

- `Secp256k1`: [Chuck Batson](https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/)
- VRF with ciphersuite `SECP256K1_SHA256_TAI`: [vrf-rs](https://github.com/witnet/vrf-rs/)

## Acknowledgements

Some EC arithmetic operations have been opmitized thanks to the impressive work of the following resources:

- Post by Vitalik Buterin in [Ethresearch](https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9)
- [SolCrypto library](https://github.com/HarryR/solcrypto)

## License

`vrf-rs` is published under the [MIT license][license].

[license]: https://github.com/witnet/vrf-rs/blob/master/LICENSE
[test-folder]: https://github.com/witnet/vrf-solidity/blob/master/test

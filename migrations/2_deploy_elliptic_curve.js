var EllipticCurve = artifacts.require("elliptic-curve-solidity/contracts/EllipticCurve.sol")
var VRF = artifacts.require("./VRF.sol")

module.exports = function (deployer, network, accounts) {
  deployer.deploy(EllipticCurve)
}

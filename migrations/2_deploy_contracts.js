var EC = artifacts.require("./EllipticCurve.sol")
var VRF = artifacts.require("./VRF.sol")

module.exports = function (deployer, network, accounts) {
  console.log("Network:", network)
  deployer.deploy(EC)
  deployer.deploy(VRF)
}

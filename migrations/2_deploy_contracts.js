var EC = artifacts.require("./EllipticCurve.sol")

module.exports = function (deployer, network, accounts) {
  console.log("Network:", network)
  deployer.deploy(EC)
}

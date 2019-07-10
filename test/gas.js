const VRFTestHelper = artifacts.require("VRFTestHelper")
const testdata = require("./vrf-data.json")

contract("VRFTestHelper - Gas consumption analysis", accounts => {
  describe("VRF verification functions:", () => {
    let helper
    before(async () => {
      helper = await VRFTestHelper.new()
    })
    it("verify()", async () => {
      for (let test of testdata.verify.valid) {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        await helper._verify(publicKey, proof, message)
      }
    })
    it("fastVerify()", async () => {
      for (let test of testdata.fastVerify.valid) {
        // Standard inputs
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const message = web3.utils.hexToBytes(test.message)
        // VRF fast verify requirements
        // U = s*B - c*Y
        const uPointX = web3.utils.toBN(test.uPoint.x)
        const uPointY = web3.utils.toBN(test.uPoint.y)
        // V = s*H - c*Gamma
        // s*H
        const vProof1X = web3.utils.toBN(test.vComponents.sH.x)
        const vProof1Y = web3.utils.toBN(test.vComponents.sH.y)
        // c*Gamma
        const vProof2X = web3.utils.toBN(test.vComponents.cGamma.x)
        const vProof2Y = web3.utils.toBN(test.vComponents.cGamma.y)
        // Check
        await helper._fastVerify(
          publicKey,
          proof,
          message,
          [uPointX, uPointY],
          [vProof1X, vProof1Y, vProof2X, vProof2Y]
        )
      }
    })
  })
  describe("VRF auxiliary public functions:", () => {
    let gas
    before(async () => {
      gas = await VRFTestHelper.new()
    })
    it("decodeProof()", async () => {
      for (let proof of testdata.proofs.valid) {
        await gas._decodeProof(web3.utils.hexToBytes(proof.pi))
      }
    })
    it("decodePoint()", async () => {
      for (let point of testdata.points.valid) {
        await gas._decodePoint(web3.utils.hexToBytes(point.compressed))
      }
    })
    it("computeFastVerifyParams()", async () => {
      for (let test of testdata.fastVerify.valid) {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await gas._decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        await gas._computeFastVerifyParams(publicKey, proof, message)
      }
    })
  })
})

const TestHelperVRF = artifacts.require("TestHelperVRF")
const truffleAssert = require("truffle-assertions")

contract("VRF", accounts => {
  const data = require("./data.json")

  describe("Auxiliary functions: ", () => {
    let helper
    before(async () => {
      helper = await TestHelperVRF.new()
    })
    for (const [index, test] of data.proofs.valid.entries()) {
      it(`should decode a VRF proof from bytes (${index + 1})`, async () => {
        const decodedProof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        assert(decodedProof[0].eq(web3.utils.toBN(test.gamma.x)))
        assert(decodedProof[1].eq(web3.utils.toBN(test.gamma.y)))
        assert(decodedProof[2].eq(web3.utils.toBN(test.c)))
        assert(decodedProof[3].eq(web3.utils.toBN(test.s)))
      })
    }
    for (const [, test] of data.proofs.invalid.entries()) {
      it(`should fail to decode a VRF proof from bytes if malformed (${test.description})`, async () => {
        await truffleAssert.reverts(helper.decodeProof.call(web3.utils.hexToBytes(test.pi)), test.revert)
      })
    }
    for (const [index, test] of data.points.valid.entries()) {
      it(`should decode a compressed EC Point (${index + 1})`, async () => {
        const coord = await helper.decodePoint.call(web3.utils.hexToBytes(test.compressed))
        assert(coord[0].eq(web3.utils.toBN(test.uncompressed.x)))
        assert(coord[1].eq(web3.utils.toBN(test.uncompressed.y)))
      })
    }
    for (const [, test] of data.points.invalid.entries()) {
      it(`should fail to decode a compressed EC Point if malformed (${test.description})`, async () => {
        await truffleAssert.reverts(helper.decodePoint.call(web3.utils.hexToBytes(test.compressed)), test.revert)
      })
    }
    for (const [index, test] of data.computeFastVerifyParams.valid.entries()) {
      it(`should compute fast verify parameters (${index + 1})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const params = await helper.computeFastVerifyParams.call(publicKey, proof, message)
        assert(params[0][0].eq(web3.utils.toBN(test.uPoint.x)))
        assert(params[0][1].eq(web3.utils.toBN(test.uPoint.y)))
        assert(params[1][0].eq(web3.utils.toBN(test.vComponents.sH.x)))
        assert(params[1][1].eq(web3.utils.toBN(test.vComponents.sH.y)))
        assert(params[1][2].eq(web3.utils.toBN(test.vComponents.cGamma.x)))
        assert(params[1][3].eq(web3.utils.toBN(test.vComponents.cGamma.y)))
      })
    }
    for (const [, test] of data.computeFastVerifyParams.invalid.entries()) {
      it(`should fail to compute fast verify parameters (${test.description})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const params = await helper.computeFastVerifyParams.call(publicKey, proof, message)
        const results = [
          params[0][0].eq(web3.utils.toBN(test.uPoint.x)),
          params[0][1].eq(web3.utils.toBN(test.uPoint.y)),
          params[1][0].eq(web3.utils.toBN(test.vComponents.sH.x)),
          params[1][1].eq(web3.utils.toBN(test.vComponents.sH.y)),
          params[1][2].eq(web3.utils.toBN(test.vComponents.cGamma.x)),
          params[1][3].eq(web3.utils.toBN(test.vComponents.cGamma.y)),
        ]
        assert(
          results.length === test.asserts.length && results.every((value, index) => value === test.asserts[index])
        )
      })
    }
  })
  describe("Proof verification functions: ", () => {
    let helper
    before(async () => {
      helper = await TestHelperVRF.new()
    })
    for (const [index, test] of data.verify.valid.entries()) {
      it(`should verify a VRF proof (${index + 1})`, async () => {
        const publicKey = await helper.decodePoint.call(web3.utils.hexToBytes(test.pub))
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const result = await helper.verify.call(publicKey, proof, message)
        assert.equal(result, true)
      })
    }
    for (const [, test] of data.verify.invalid.entries()) {
      it(`should return false when verifying an invalid VRF proof (${test.description})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const result = await helper.verify.call(publicKey, proof, message)
        assert.equal(result, false)
      })
    }
    for (const [index, test] of data.fastVerify.valid.entries()) {
      it(`should fast verify a VRF proof (${index + 1})`, async () => {
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
        const res = await helper.fastVerify.call(
          publicKey,
          proof,
          message,
          [uPointX, uPointY],
          [vProof1X, vProof1Y, vProof2X, vProof2Y]
        )
        assert.equal(res, true)
      })
    }
    for (const [, test] of data.fastVerify.invalid.entries()) {
      it(`should return false when fast verifying an invalid VRF proof (${test.description})`, async () => {
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
        const res = await helper.fastVerify.call(
          publicKey,
          proof,
          message,
          [uPointX, uPointY],
          [vProof1X, vProof1Y, vProof2X, vProof2Y]
        )
        assert.equal(res, false)
      })
    }
  })
  describe("VRF hash output function: ", () => {
    let helper
    before(async () => {
      helper = await TestHelperVRF.new()
    })
    for (const [index, test] of data.verify.valid.entries()) {
      it(`should generate hash output from VRF proof (${index + 1})`, async () => {
        const proof = await helper.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const hash = await helper.gammaToHash.call(proof[0], proof[1])
        assert.equal(hash, test.hash)
      })
    }
  })
})

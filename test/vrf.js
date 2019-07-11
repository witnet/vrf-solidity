const VRF = artifacts.require("VRF")
const testdata = require("./testdata.json")

contract("VRF", accounts => {
  describe("Auxiliary functions: ", () => {
    let vrf
    before(async () => {
      vrf = await VRF.deployed()
    })
    for (let [index, proof] of testdata.proofs.valid.entries()) {
      it(`should decode a VRF proof from bytes (${index + 1})`, async () => {
        const decodedProof = await vrf.decodeProof.call(web3.utils.hexToBytes(proof.pi))
        assert(decodedProof[0].eq(web3.utils.toBN(proof.gamma.x)))
        assert(decodedProof[1].eq(web3.utils.toBN(proof.gamma.y)))
        assert(decodedProof[2].eq(web3.utils.toBN(proof.c)))
        assert(decodedProof[3].eq(web3.utils.toBN(proof.s)))
      })
    }
    for (let [index, point] of testdata.points.valid.entries()) {
      it(`should decode a compressed EC Point (${index + 1})`, async () => {
        const coord = await vrf.decodePoint.call(web3.utils.hexToBytes(point.compressed))
        assert(coord[0].eq(web3.utils.toBN(point.uncompressed.x)))
        assert(coord[1].eq(web3.utils.toBN(point.uncompressed.y)))
      })
    }
    for (let [index, test] of testdata.fastVerify.valid.entries()) {
      it(`should compute fast verify parameters (${index + 1})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const params = await vrf.computeFastVerifyParams.call(publicKey, proof, message)
        assert(params[0][0].eq(web3.utils.toBN(test.uPoint.x)))
        assert(params[0][1].eq(web3.utils.toBN(test.uPoint.y)))
        assert(params[1][0].eq(web3.utils.toBN(test.vComponents.sH.x)))
        assert(params[1][1].eq(web3.utils.toBN(test.vComponents.sH.y)))
        assert(params[1][2].eq(web3.utils.toBN(test.vComponents.cGamma.x)))
        assert(params[1][3].eq(web3.utils.toBN(test.vComponents.cGamma.y)))
      })
    }
  })
  describe("Proof verification functions: ", () => {
    let vrf
    before(async () => {
      vrf = await VRF.deployed()
    })
    for (let [index, test] of testdata.verify.valid.entries()) {
      it(`should verify a VRF proof (${index + 1})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const result = await vrf.verify.call(publicKey, proof, message)
        assert.equal(result, true)
      })
    }
    for (let [index, test] of testdata.verify.invalid.entries()) {
      it(`should not verify a VRF proof (${index + 1}) - ${test.description}`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(test.pi))
        const message = web3.utils.hexToBytes(test.message)
        const result = await vrf.verify.call(publicKey, proof, message)
        assert.equal(result, false)
      })
    }
    for (let [index, test] of testdata.fastVerify.valid.entries()) {
      it(`should fast verify a VRF proof (${index + 1})`, async () => {
        // Standard inputs
        const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(test.pi))
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
        const res = await vrf.fastVerify.call(
          publicKey,
          proof,
          message,
          [uPointX, uPointY],
          [vProof1X, vProof1Y, vProof2X, vProof2Y]
        )
        assert.equal(res, true)
      })
    }
  })
})

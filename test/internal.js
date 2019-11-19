const TestHelperVRF = artifacts.require("TestHelperInternals")
const data = require("./data.json")

contract("VRF - internals", accounts => {
  describe("VRF underlying algorithms: ", () => {
    let helper
    before(async () => {
      helper = await TestHelperVRF.new()
    })
    for (const [, test] of data.hashToTryAndIncrement.valid.entries()) {
      it(`Hash to Try And Increment (TAI) (${test.description})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const message = web3.utils.hexToBytes(test.message)
        const result = await helper.hashToTryAndIncrement.call(publicKey, message)
        assert(result[0].eq(web3.utils.toBN(test.hashPoint.x)))
        assert(result[1].eq(web3.utils.toBN(test.hashPoint.y)))
      })
    }
    for (const [index, test] of data.hashPoints.valid.entries()) {
      it(`Points to hash (digest from EC points) (${index + 1})`, async () => {
        const res = await helper.hashPoints.call(
          web3.utils.hexToBytes(test.hPoint.x),
          web3.utils.hexToBytes(test.hPoint.y),
          web3.utils.hexToBytes(test.gamma.x),
          web3.utils.hexToBytes(test.gamma.y),
          web3.utils.hexToBytes(test.uPoint.x),
          web3.utils.hexToBytes(test.uPoint.y),
          web3.utils.hexToBytes(test.vPoint.x),
          web3.utils.hexToBytes(test.vPoint.y))
        assert.equal(res.toString(), test.hash)
      })
    }
  })
  describe("VRF internal aux. functions: ", () => {
    let helper
    before(async () => {
      helper = await TestHelperVRF.new()
    })
    for (const [index, point] of data.points.valid.entries()) {
      it(`should encode an EC point to compressed format (${index + 1})`, async () => {
        const res = await helper.encodePoint.call(point.uncompressed.x, point.uncompressed.y)
        assert.equal(res, point.compressed)
      })
    }
    for (const [index, test] of data.ecMulSubMul.valid.entries()) {
      it(`should do an ecMulSubMul operation (${index + 1})`, async () => {
        const res = await helper.ecMulSubMul.call(test.scalar1, test.a1, test.a2, test.scalar2, test.b1, test.b2)
        assert(res[0].eq(web3.utils.toBN(test.output.x)))
        assert(res[1].eq(web3.utils.toBN(test.output.y)))
      })
    }
    for (const [index, test] of data.ecMul.valid.entries()) {
      it(`should verify an ecMul operation (ecrecover hack) (${index + 1})`, async () => {
        const res = await helper.ecMulVerify.call(test.scalar, test.x, test.y, test.output.x, test.output.y)
        assert.equal(res, true)
      })
    }
    for (const [index, test] of data.ecMulSubMulVerify.valid.entries()) {
      it(`should verify an ecMulSubMul operation (ecrecover hack enhanced) (${index + 1})`, async () => {
        const res = await helper.ecMulSubMulVerify.call(
          test.scalar1,
          test.scalar2,
          test.x,
          test.y,
          test.output.x,
          test.output.y)
        assert.equal(res, true)
      })
    }
  })
})

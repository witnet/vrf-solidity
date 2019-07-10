const VRFTestHelper = artifacts.require("VRFTestHelper")
const testdata = require("./internal-data.json")

contract("VRFTestHelper - internals", accounts => {
  describe("VRF underlying algorithms: ", () => {
    let helper
    before(async () => {
      helper = await VRFTestHelper.new()
    })
    for (let [index, test] of testdata.hashToTryAndIncrement.valid.entries()) {
      it(`Hash to Try And Increment (TAI) (${index + 1}) - (${test.description})`, async () => {
        const publicKeyX = web3.utils.hexToBytes(test.publicKey.x)
        const publicKeyY = web3.utils.hexToBytes(test.publicKey.y)
        const publicKey = [publicKeyX, publicKeyY]
        const message = web3.utils.hexToBytes(test.message)
        const result = await helper._hashToTryAndIncrement.call(publicKey, message)
        assert.equal(web3.utils.numberToHex(result[0]), test.hashPoint.x)
        assert.equal(web3.utils.numberToHex(result[1]), test.hashPoint.y)
      })
    }
  })
})

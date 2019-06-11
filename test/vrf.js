const BN = web3.utils.BN
const VRF = artifacts.require("VRF")
const crypto = require("crypto")

contract("VRF", accounts => {
  describe("VRF required operations", () => {
    var n = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    // const gx = new BN("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    // const gy = new BN("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    // const n2 = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    const hash = crypto.createHash("sha256")

    let vrf
    before(async () => {
      vrf = await VRF.deployed()
    })
    it("should Add two small numbers", async () => {
      var x1 = new BN(2)
      var z1 = new BN(3)
      var x2 = new BN(4)
      var z2 = new BN(5)
      const res = await vrf.add(x1, z1, x2, z2)
      var x3 = res[0]
      var z3 = res[1]
      assert.equal(x3.toString(10), "22")
      assert.equal(z3.toString(10), "15")
    })
    // To be continued...

    it("should convert a uint to bytes", async () => {
      const res = await vrf.uint256ToBytes(4)
      assert.equal(res.toString(), "0x0000000000000000000000000000000000000000000000000000000000000004")
    })

    it("should merge prefix and bytes", async () => {
      const prefix = web3.utils.hexToBytes("0x02")
      let data = web3.utils.hexToBytes("0xffffffff")
      const res = await vrf.mergeBytes(prefix, data)
      assert.equal(res.toString(), "0x02ffffffff")
    })

    it("should encode an even point using the compressed binary format", async () => {
      const pointX = web3.utils.hexToBytes("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
      const pointY = web3.utils.hexToBytes("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
      const res = await vrf.point_to_bytes(pointX, pointY)
      assert.equal(res.toString(), "0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".toLowerCase())
    })

    it("should encode an odd point using the compressed binary format", async () => {
      const pointX = web3.utils.hexToBytes("0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      const pointY = web3.utils.hexToBytes("0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297")
      const res = await vrf.point_to_bytes(pointX, pointY)
      assert.equal(res.toString(), "0x03FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556".toLowerCase())
    })

    it("should do a digest from several EC points", async () => {
      const pointX = web3.utils.hexToBytes("0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      const pointY = web3.utils.hexToBytes("0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297")
      const res = await vrf.hash_points(pointX, pointY, pointX, pointY, pointX, pointY, pointX, pointY)
      const toBeHashed = web3.utils.hexToBytes("0x0203FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      hash.update(Buffer.from(toBeHashed))
      const expected = hash.digest("hex").slice(0, 32)
      assert.equal(res.toString().slice(2), expected)
    })
  })
})

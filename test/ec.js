const BN = web3.utils.BN
const EC = artifacts.require("EllipticCurve")

contract("EC", accounts => {
  describe("EC curve", () => {
    var n = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    // const gx = new BN("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    // const gy = new BN("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    // const n2 = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    let ec
    before(async () => {
      ec = await EC.deployed()
    })
    it("Should Add two small numbers", async () => {
      var x1 = new BN(2)
      var z1 = new BN(3)
      var x2 = new BN(4)
      var z2 = new BN(5)
      const res = await ec._jAdd(x1, z1, x2, z2)
      var x3 = res[0]
      var z3 = res[1]
      assert.equal(x3.toString(10), "22")
      assert.equal(z3.toString(10), "15")
    })
    it("Should Add one big numbers with one small", async () => {
      var x1 = n.sub(web3.utils.toBN("1"))
      var z1 = new BN(1)
      var x2 = new BN(2)
      var z2 = new BN(1)
      const res = await ec._jAdd(x1, z1, x2, z2)
      var x3 = res[0]
      var z3 = res[1]
      assert.equal(x3.toString(10), "1")
      assert.equal(z3.toString(10), "1")
    })
    // To be continued...
  })
})

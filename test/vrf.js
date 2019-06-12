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
      // Prefixes: FE02
      const toBeHashed = web3.utils.hexToBytes("0xFE0203FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      hash.update(Buffer.from(toBeHashed))
      const expected = hash.digest("hex").slice(0, 32)
      assert.equal(res.toString().slice(2), expected)
    })

    it("should decompress an EC point", async () => {
      const coordX = "0xc2704fed5dc41d3979235b85edda8f86f1806c17ce0a516a034c605d2b4f9a26"
      const coordY = "0x6970c3dd18910d09250143db08fed1065a522403df0c204ed240a07d123b29d5"
      const point = await vrf.decompress.call(3, web3.utils.hexToBytes(coordX))
      assert.equal(web3.utils.numberToHex(point[0]), coordX)
      assert.equal(web3.utils.numberToHex(point[1]), coordY)
    })

    it("should verify a valid VRF proof", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]

      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      let proof = []

      const gammaYSign = pi.slice(0, 2)
      const gammaX = web3.utils.hexToBytes("0x".concat(pi.slice(2, 2 + 64)))
      const gamma = await vrf.decompress.call(gammaYSign, gammaX)
      proof[0] = gamma[0]
      proof[1] = gamma[1]

      const c = web3.utils.hexToBytes("0x".concat(pi.slice(66, 2 + 64 + 32)))
      const s = web3.utils.hexToBytes("0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64)))
      proof[2] = c
      proof[3] = s

      // ASCII: sample
      // const message = web3.utils.hexToBytes("0x73616d706c65")

      // Instead of deriving H from message, we provide a H point
      const hashPoint = "02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      // hashPointY := 0x9fb51558a73827c2571280f89adb0fe5626497ef54061836d2c83bb101d88ac
      const hashSign = hashPoint.slice(0, 2)
      const hashX = web3.utils.hexToBytes("0x".concat(hashPoint.slice(2, 66)))
      const hPoint = await vrf.decompress.call(hashSign, hashX)
      // console.log("hashPointY: ", web3.utils.numberToHex(hPoint[1]))

      const result = await vrf.verify.call(publicKey, proof, hPoint)
      assert.ok(result)
    })

    it("should fail in VRF verify with wrong hash point", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]

      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      let proof = []

      const gammaYSign = pi.slice(0, 2)
      const gammaX = web3.utils.hexToBytes("0x".concat(pi.slice(2, 2 + 64)))
      const gamma = await vrf.decompress.call(gammaYSign, gammaX)
      proof[0] = gamma[0]
      proof[1] = gamma[1]

      const c = web3.utils.hexToBytes("0x".concat(pi.slice(66, 2 + 64 + 32)))
      const s = web3.utils.hexToBytes("0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64)))
      proof[2] = c
      proof[3] = s

      // wrong coordinate Y
      const hashPoint = "03397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      const hashSign = hashPoint.slice(0, 2)
      const hashX = web3.utils.hexToBytes("0x".concat(hashPoint.slice(2, 66)))
      const hPoint = await vrf.decompress.call(hashSign, hashX)

      const result = await vrf.verify.call(publicKey, proof, hPoint)
      assert.equal(result, false)
    })
  })
})

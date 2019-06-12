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
      // public key
      // prefix: 04 (uncompressed)
      // coordX: [2c, 8c, 31, fc, 9f, 99, c, 6b, 55, e3, 86, 5a, 18, 4a, 4c, e5, e, 9, 48, 1f, 2e, ae, b3, e6, e, c1, ce, a1, 3a, 6a, e6, 45]
      // coordY: [64, b9, 5e, 4f, db, 69, 48, c0, 38, 6e, 18, 9b, 0, 6a, 29, f6, 86, 76, 9b, 1, 17, 4, 27, 5e, 44, 59, 82, 2d, c3, 32, 80, 85]
      
      // c (16 bytes)
      // 14FAA89697B482DAA377FB6B4A8B0191

      // s (32 bytes)
      // A65D34A6D90A8A2461E5DB9205D4CF0BB4B2C31B5EF6997A585A9F1A72517B6F

      // H point
      // [4
      // coordX: 39, 7a, 91, 59, 43, d5, c8, 19, 2c, 79, fe, a8, a4, b6, d4, 5b, e4, 1e, a, 9a, e2, 72, 2c, 1e, 19, 2a, 0, 9c, b9, f3, 8c, e3
      // coordY: 9, fb, 51, 55, 8a, 73, 82, 7c, 25, 71, 28, f, 89, ad, b0, fe, 56, 26, 49, 7e, f5, 40, 61, 83, 6d, 2c, 83, bb, 10, 1d, 88, ac]

      // u point
      // prefix: 04
      // coordX: c71cd5625cd61d65bd9f6b84292eae013fc50ea99a9a090c730c3a4c24c32cc7
      // coordY: ebe10326af2accc2f3a4eb8658d90e572061aa766d04e31f102b26e7065c9f26

      // sH
      // prefix: 04 
      // coord X: 0x3596f1f475c8999ffe35ccf7cebee7373ee40513ad467e3fc38600aa06d41bcf
      // coord Y: 0x825a3eb4f09a55637391c950ba5e25c1ea658a15f234c14ebec79e5c68bd4133

      // cGamma
      // coordX: 0x1c2a90c4c30f60e878d1fe317acf4f2e059300e3deaa1c949628096ecaf993b2
      // coordY: 0x9d42bf0c35d765c2242712205e8f8b1ea588f470a6980b21bc9efb4ab33ae246

      // CGamma inverted
      // coordX: 0x1c2a90c4c30f60e878d1fe317acf4f2e059300e3deaa1c949628096ecaf993b2,
      // coordY: 0x62bd40f3ca289a3ddbd8eddfa17074e15a770b8f5967f4de436104b44cc519e9

      // v point
      // prefix: 04
      // coordX: 0x957f0c13905d357d9e1ebaf32742b410d423fcf2410229d4e8093f3360d07b2c
      // coordY: 0x9a0d14288d3906e052bdcf12c2a469da3e7449068b3e119300b792da964ed977

      // to be hashed
      // fe
      // 02
      // 02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3031f4d
      // bca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0802c71cd5625cd61d
      // 65bd9f6b84292eae013fc50ea99a9a090c730c3a4c24c32cc703957f0c13905d357d9e1ebaf3
      // 2742b410d423fcf2410229d4e8093f3360d07b2c

      // derived_c (16 bytes)
      // 14FAA89697B482DAA377FB6B4A8B0191

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
      const message = web3.utils.hexToBytes("0x73616d706c65")

      const hashPoint = "02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      // hashPointY := 0x9fb51558a73827c2571280f89adb0fe5626497ef54061836d2c83bb101d88ac
      const hashSign = hashPoint.slice(0, 2)
      const hashX = web3.utils.hexToBytes("0x".concat(hashPoint.slice(2, 66)))
      const hPoint = await vrf.decompress.call(hashSign, hashX)
      // console.log("hashPointY: ", web3.utils.numberToHex(hPoint[1]))

      const result = await vrf.verify.call(publicKey, proof, message, hPoint)

      assert.ok(result)

      // const ghx = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      // const gamma2 = await vrf.decompress.call(2, ghx)
      // const gamma3 = await vrf.decompress.call(3, ghx)

      // console.log("gamme 2: ", web3.utils.numberToHex(gamma2[1]))
      // console.log("gamma 3: ", web3.utils.numberToHex(gamma3[1]))

      // console.log("derived  c", web3.utils.numberToHex(derived_c))
      // console.log("original c", "0x".concat(pi.slice(66, 2 + 64 + 32)))
      // console.log("original s", "0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64)))
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
      const message = web3.utils.hexToBytes("0x73616d706c65")

      const hashPoint = "02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      // hashPointY := 0x9fb51558a73827c2571280f89adb0fe5626497ef54061836d2c83bb101d88ac
      const hashSign = hashPoint.slice(0, 2)
      const hashX = web3.utils.hexToBytes("0x".concat(hashPoint.slice(2, 66)))
      const hPoint = await vrf.decompress.call(hashSign, hashX)
      // console.log("hashPointY: ", web3.utils.numberToHex(hPoint[1]))

      const result = await vrf.verify.call(publicKey, proof, message, hPoint)

      assert.equal(result, false)
    })
  })
})

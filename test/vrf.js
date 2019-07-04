const VRF = artifacts.require("VRF")
const crypto = require("crypto")

contract("VRF", accounts => {
  describe("VRF required operations", () => {
    const hash = crypto.createHash("sha256")

    let vrf
    before(async () => {
      vrf = await VRF.deployed()
    })

    it("should encode an even point using the compressed binary format", async () => {
      const pointX = web3.utils.hexToBytes("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
      const pointY = web3.utils.hexToBytes("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
      const res = await vrf.encodePoint(pointX, pointY)
      assert.equal(res.toString(), "0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".toLowerCase())
    })

    it("should encode an odd point using the compressed binary format", async () => {
      const pointX = web3.utils.hexToBytes("0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      const pointY = web3.utils.hexToBytes("0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297")
      const res = await vrf.encodePoint(pointX, pointY)
      assert.equal(res.toString(), "0x03FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556".toLowerCase())
    })

    it("should do a digest from several EC points", async () => {
      const pointX = web3.utils.hexToBytes("0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      const pointY = web3.utils.hexToBytes("0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297")
      const res = await vrf.hashPoints(pointX, pointY, pointX, pointY, pointX, pointY, pointX, pointY)
      // Prefixes: FE02
      const toBeHashed = web3.utils.hexToBytes("0xFE0203FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755603FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556")
      hash.update(Buffer.from(toBeHashed))
      const expected = hash.digest("hex").slice(0, 32)
      assert.equal(res.toString().slice(2), expected)
    })

    it("should compute the coordinate Y from a coordinate X and a sign", async () => {
      const coordX = "0xc2704fed5dc41d3979235b85edda8f86f1806c17ce0a516a034c605d2b4f9a26"
      const expectedCoordY = "0x6970c3dd18910d09250143db08fed1065a522403df0c204ed240a07d123b29d5"
      const coordY = await vrf.deriveY.call(3, web3.utils.hexToBytes(coordX))
      assert.equal(web3.utils.numberToHex(coordY), expectedCoordY)
    })

    it("should decode a compressed EC Point", async () => {
      const ecPoint = "0x03c2704fed5dc41d3979235b85edda8f86f1806c17ce0a516a034c605d2b4f9a26"
      const expectedCoordX = "0xc2704fed5dc41d3979235b85edda8f86f1806c17ce0a516a034c605d2b4f9a26"
      const expectedCoordY = "0x6970c3dd18910d09250143db08fed1065a522403df0c204ed240a07d123b29d5"
      const coord = await vrf.decodePoint.call(web3.utils.hexToBytes(ecPoint))
      assert.equal(web3.utils.numberToHex(coord[0]), expectedCoordX)
      assert.equal(web3.utils.numberToHex(coord[1]), expectedCoordY)
    })

    it("should verify a valid VRF proof (no decode proof)", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]

      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      let proof = []

      const gammaHex = web3.utils.hexToBytes("0x".concat(pi.slice(0, 66)))
      const gamma = await vrf.decodePoint.call(gammaHex)
      proof[0] = gamma[0]
      proof[1] = gamma[1]

      const c = web3.utils.hexToBytes("0x".concat(pi.slice(66, 2 + 64 + 32)))
      const s = web3.utils.hexToBytes("0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64)))
      proof[2] = c
      proof[3] = s

      // ASCII: sample
      // const message = web3.utils.hexToBytes("0x73616d706c65")
      // Instead of deriving H from message, we provide a H point
      const hashPoint = "0x02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      const hPoint = await vrf.decodePoint.call(web3.utils.hexToBytes(hashPoint))

      const result = await vrf.verify.call(publicKey, proof, hPoint)
      assert.equal(result, true)
    })

    it("should fail in VRF verify with wrong hash point (no decode proof)", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]

      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      let proof = []

      const gammaHex = web3.utils.hexToBytes("0x".concat(pi.slice(0, 66)))
      const gamma = await vrf.decodePoint.call(gammaHex)
      proof[0] = gamma[0]
      proof[1] = gamma[1]

      const c = web3.utils.hexToBytes("0x".concat(pi.slice(66, 2 + 64 + 32)))
      const s = web3.utils.hexToBytes("0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64)))
      proof[2] = c
      proof[3] = s

      // wrong sign of coordinate Y
      const hashPoint = "0x03397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      const hPoint = await vrf.decodePoint.call(web3.utils.hexToBytes(hashPoint))

      const result = await vrf.verify.call(publicKey, proof, hPoint)
      assert.equal(result, false)
    })

    it("should decode proof bytes", async () => {
      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      const gammaPoint = web3.utils.hexToBytes("0x".concat(pi.slice(0, 66)))
      const gamma = await vrf.decodePoint.call(gammaPoint)
      const cHex = "0x".concat(pi.slice(66, 2 + 64 + 32))
      const sHex = "0x".concat(pi.slice(2 + 64 + 32, 2 + 64 + 32 + 64))

      const piHex = "0x".concat(pi)
      const decodedProof = await vrf.decodeProof.call(web3.utils.hexToBytes(piHex))
      // gammaX
      assert.equal(web3.utils.numberToHex(decodedProof[0]), web3.utils.numberToHex(gamma[0]))
      // gammaY
      assert.equal(web3.utils.numberToHex(decodedProof[1]), web3.utils.numberToHex(gamma[1]))
      // c
      assert.equal(web3.utils.numberToHex(decodedProof[2]), cHex)
      // s
      assert.equal(web3.utils.numberToHex(decodedProof[3]), sHex)
    })

    it("should verify proof (with decode proof)", async () => {
      const pi = "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"

      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]

      const piHex = "0x".concat(pi)
      const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(piHex))

      // Instead of deriving H from message, we provide a H point
      const hashPoint = "0x02397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      const hPoint = await vrf.decodePoint.call(web3.utils.hexToBytes(hashPoint))

      const result = await vrf.verify.call(publicKey, proof, hPoint)
      assert.equal(result, true)
    })

    it("should provide a valid hash point on 1st iteration", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]
      const message = web3.utils.hexToBytes("0x73616d706c65")

      // the H point for the previous message
      const expectedHashX = "0x397a915943d5c8192c79fea8a4b6d45be41e0a9ae2722c1e192a009cb9f38ce3"
      const expectedHashY = "0x9fb51558a73827c2571280f89adb0fe5626497ef54061836d2c83bb101d88ac"
      const result = await vrf.hashToTryAndIncrement.call(publicKey, message)
      assert.equal(web3.utils.numberToHex(result[0]), expectedHashX)
      assert.equal(web3.utils.numberToHex(result[1]), expectedHashY)
    })

    it("should verify proof with message", async () => {
      const pi = "0x031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f"
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]
      const proof = await vrf.decodeProof.call(web3.utils.hexToBytes(pi))
      const message = web3.utils.hexToBytes("0x73616d706c65")
      const result = await vrf.verifyMessage.call(publicKey, proof, message)
      assert.equal(result, true)
    })

    it("should provide a valid hash point after 6 iterations", async () => {
      const publicKeyX = web3.utils.hexToBytes("0x2c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
      const publicKeyY = web3.utils.hexToBytes("0x64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085")
      const publicKey = [publicKeyX, publicKeyY]
      const message = web3.utils.hexToBytes("0x73616d706c77")

      // the H point for the previous message (after six iterations)
      // prefix: 04
      // coordX: e906a3b4379ddbff598994b2ff026766fb66424710776099b85111f23f8eebcc
      // coordY: 7638965bf85f5f2b6641324389ef2ffb99576ba72ec19d8411a5ea1dd251b112

      const expectedHashX = "0xe906a3b4379ddbff598994b2ff026766fb66424710776099b85111f23f8eebcc"
      const expectedHashY = "0x7638965bf85f5f2b6641324389ef2ffb99576ba72ec19d8411a5ea1dd251b112"
      const result = await vrf.hashToTryAndIncrement.call(publicKey, message)
      assert.equal(web3.utils.numberToHex(result[0]), expectedHashX)
      assert.equal(web3.utils.numberToHex(result[1]), expectedHashY)
    })
  })
})

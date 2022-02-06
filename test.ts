// @ts-ignore
import {encode} from "fastestsmallesttextencoderdecoder";
import {Blake3, arraycopy} from "./blake3"

const testBytes = encode("This is a string")
const testKeyedHashBytes = new Uint8Array([0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]);

const testVectorData = new Uint8Array(251);
for (let i = 0; i < testVectorData.length; i++) {
    testVectorData[i] = i;
}

function getTestVectorInput(inputLen: number): Int8Array {
    let remainder = testVectorData.slice(0, inputLen % 251);
    let input = new Int8Array(inputLen);

    let x = 0;
    while (x + 251 < inputLen) {
        arraycopy(testVectorData, 0, input, x, 251);
        x += 251;
    }
    arraycopy(remainder, 0, input, inputLen - remainder.length, remainder.length);
    return input;
}

describe("Blake 3 test suite", function () {
    it("basicHash", function () {
        const hasher = Blake3.newInstance();
        hasher.update(testBytes);
        expect(hasher.hexdigest()).toBe("718b749f12a61257438b2ea6643555fd995001c9d9ff84764f93f82610a780f2");
    });
    it("longerHash", function () {
        const hasher = Blake3.newInstance();
        hasher.update(testBytes);
        expect(hasher.hexdigest(128)).toBe("718b749f12a61257438b2ea6643555fd995001c9d9ff84764f93f82610a780f243a9903464658159cf8b216e79006e12ef3568851423fa7c97002cbb9ca4dc44b4185bb3c6d18cdd1a991c2416f5e929810290b24bf24ba6262012684b6a0c4e096f55e8b0b4353c7b04a1141d25afd71fffae1304a5abf0c44150df8b8d4017");
    });
    it("shorterHash", function () {
        const hasher = Blake3.newInstance();
        hasher.update(testBytes);
        expect(hasher.hexdigest(16)).toBe("718b749f12a61257438b2ea6643555fd");
    });
    it("rawByteHash", function () {
        const hasher = Blake3.newInstance();
        hasher.update(testBytes);
        let digest = hasher.digest();
        expect(digest).toEqual(new Int8Array([113, -117, 116, -97, 18, -90, 18, 87, 67, -117, 46, -90, 100, 53, 85, -3, -103, 80, 1, -55, -39, -1, -124, 118, 79, -109, -8, 38, 16, -89, -128, -14]));
    });
    it("kdfHasher", function () {
        const hasher = Blake3.newKeyDerivationHasher("meowmeowverysecuremeowmeow");
        hasher.update(testBytes);
        expect(hasher.hexdigest()).toEqual("348de7e5f8f804216998120d1d05c6d233d250bdf40220dbf02395c1f89a73f7");
    });

    it("officialTestVectors", function () {
        const json = require('./test_vectors.json')
        const contextString = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        const key = json["key"];
        const cases = json["cases"]

        for (let i = 0; i < cases.length; i++) {
            let testCase = cases[i]
            let inputLen = Number(testCase["input_len"]);
            let inputData = getTestVectorInput(inputLen);
            const blake3 = Blake3.newInstance();
            const keyed = Blake3.newKeyedHasher(encode(key)); // Technically ASCII, let's try it as UTF-8.
            const kdf = Blake3.newKeyDerivationHasher(contextString);

            blake3.update(inputData);
            keyed.update(inputData);
            kdf.update(inputData);

            expect(testCase["hash"]).toEqual(blake3.hexdigest(131));
            expect(testCase["keyed_hash"]).toEqual(keyed.hexdigest(131));
            expect(testCase["derive_key"]).toEqual(kdf.hexdigest(131));

            expect(testCase["hash"].substring(0, 64)).toEqual(blake3.hexdigest());
            expect(testCase["keyed_hash"].substring(0, 64)).toEqual(keyed.hexdigest());
            expect(testCase["derive_key"].substring(0, 64)).toEqual(kdf.hexdigest());
        }
    })
});
    
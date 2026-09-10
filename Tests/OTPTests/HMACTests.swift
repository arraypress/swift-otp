//
//  HMACTests.swift
//  OTP
//
//  RFC 4231 cases 1–4 and RFC 2202's first two, then the wire forms.
//

import XCTest
@testable import OTP

final class HMACTests: XCTestCase {

    private let cases: [(key: Data, message: Data, sha256: String, sha384: String, sha512: String)] = [
        (Fixtures.bytes(0x0b, count: 20), Data("Hi There".utf8),
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
         "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
        (Data("Jefe".utf8), Data("what do ya want for nothing?".utf8),
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
         "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
         "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
        (Fixtures.bytes(0xaa, count: 20), Fixtures.bytes(0xdd, count: 50),
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
         "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
         "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
        (Data((1...25).map { UInt8($0) }), Fixtures.bytes(0xcd, count: 50),
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
         "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
         "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
    ]

    func testTheRFC4231Vectors() throws {
        for (index, vector) in cases.enumerated() {
            XCTAssertEqual(try HMAC.sign(vector.message, key: vector.key, algorithm: .sha256).hex, vector.sha256, "case \(index + 1) sha256")
            XCTAssertEqual(try HMAC.sign(vector.message, key: vector.key, algorithm: .sha384).hex, vector.sha384, "case \(index + 1) sha384")
            XCTAssertEqual(try HMAC.sign(vector.message, key: vector.key, algorithm: .sha512).hex, vector.sha512, "case \(index + 1) sha512")
        }
    }

    func testTheRFC2202SHA1Vectors() throws {
        XCTAssertEqual(try HMAC.sign(Data("Hi There".utf8), key: Fixtures.bytes(0x0b, count: 20), algorithm: .sha1).hex,
                       "b617318655057264e28bc0b6fb378c8ef146be00")
        XCTAssertEqual(try HMAC.sign("what do ya want for nothing?", key: "Jefe", algorithm: .sha1).hex,
                       "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
    }

    func testTextConvenienceIsUTF8() throws {
        XCTAssertEqual(try HMAC.sign("what do ya want for nothing?", key: "Jefe").hex,
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(try HMAC.sign("héllo", key: "k").data, try HMAC.sign(Data("héllo".utf8), key: Data("k".utf8)).data)
    }

    func testVerifyAcceptsTheRightSignatureInEveryForm() throws {
        let message = Data("what do ya want for nothing?".utf8), key = Data("Jefe".utf8)
        let signature = try HMAC.sign(message, key: key)
        XCTAssertTrue(try HMAC.verify(signature, message: message, key: key))
        XCTAssertTrue(try HMAC.verify(signature.data, message: message, key: key, algorithm: .sha256))
        XCTAssertTrue(try HMAC.verify(hex: signature.hex, message: message, key: key))
        XCTAssertTrue(try HMAC.verify(hex: signature.hex.uppercased(), message: message, key: key))
        XCTAssertTrue(try HMAC.verify(hex: "0x" + signature.hex, message: message, key: key))
        XCTAssertTrue(try HMAC.verify(base64: signature.base64, message: message, key: key))
        XCTAssertEqual(signature.base64, "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM=")
    }

    func testVerifyRejectsOneWrongByteAnywhere() throws {
        let message = Data("what do ya want for nothing?".utf8), key = Data("Jefe".utf8)
        let signature = try HMAC.sign(message, key: key)
        for index in [0, 1, 15, 31] {
            var tampered = signature.data
            tampered[index] ^= 0x01
            XCTAssertFalse(try HMAC.verify(tampered, message: message, key: key, algorithm: .sha256), "byte \(index)")
        }
        XCTAssertFalse(try HMAC.verify(signature.data.dropLast(), message: message, key: key, algorithm: .sha256), "short")
        XCTAssertFalse(try HMAC.verify(signature.data + [0], message: message, key: key, algorithm: .sha256), "long")
        XCTAssertFalse(try HMAC.verify(Data(), message: message, key: key, algorithm: .sha256), "empty")
        XCTAssertFalse(try HMAC.verify(signature, message: message, key: Data("jefe".utf8)), "other key")
        XCTAssertFalse(try HMAC.verify(signature, message: Data("what do ya want for nothing!".utf8), key: key), "other message")
        XCTAssertFalse(try HMAC.verify(Signature(data: signature.data, algorithm: .sha1), message: message, key: key), "other algorithm")
    }

    func testAWebhookTheWayGitHubAndStripeSendIt() throws {
        // GitHub: X-Hub-Signature-256: sha256=<hex of HMAC(secret, body)>.
        let body = Data(#"{"action":"opened","number":1}"#.utf8)
        let header = "sha256=" + (try HMAC.sign(body, key: Data("s3cret".utf8)).hex)
        let hex = String(header.dropFirst("sha256=".count))
        XCTAssertTrue(try HMAC.verify(hex: hex, message: body, key: Data("s3cret".utf8)))
        XCTAssertFalse(try HMAC.verify(hex: hex, message: body + [0x0a], key: Data("s3cret".utf8)))
        // Stripe: signed_payload is "<timestamp>.<body>", v1=<hex>.
        let signed = Data("1492774577.".utf8) + body
        let v1 = try HMAC.sign(signed, key: Data("whsec_test".utf8)).hex
        XCTAssertTrue(try HMAC.verify(hex: v1, message: signed, key: Data("whsec_test".utf8)))
    }

    func testAnEmptyKeyIsRefused() {
        XCTAssertThrowsError(try HMAC.sign(Data("x".utf8), key: Data())) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        XCTAssertThrowsError(try HMAC.sign("x", key: ""))
        XCTAssertThrowsError(try HMAC.verify(Data(), message: Data(), key: Data(), algorithm: .sha256))
        XCTAssertNoThrow(try HMAC.sign(Data(), key: Data("k".utf8)), "an empty message is fine")
    }

    func testBadWireFormsAreNamed() {
        XCTAssertThrowsError(try Signature(hex: "abc", algorithm: .sha256)) { XCTAssertEqual($0 as? OTPError, .badHex("abc")) }
        XCTAssertThrowsError(try Signature(hex: "zz", algorithm: .sha256)) { XCTAssertEqual($0 as? OTPError, .badHex("zz")) }
        XCTAssertThrowsError(try Signature(hex: "", algorithm: .sha256))
        XCTAssertThrowsError(try Signature(base64: "not base64!", algorithm: .sha256)) { XCTAssertEqual($0 as? OTPError, .badBase64("not base64!")) }
        XCTAssertEqual(try Signature(hex: "00ff", algorithm: .sha1).data, Data([0x00, 0xff]))
        XCTAssertEqual(Rendering.hex(Data([0x00, 0x0a, 0xff])), "000aff")
    }

    func testDigestLengths() throws {
        XCTAssertEqual(HashAlgorithm.allCases.map(\.digestLength), [20, 32, 48, 64])
        for algorithm in HashAlgorithm.allCases {
            XCTAssertEqual(try HMAC.sign("m", key: "k", algorithm: algorithm).data.count, algorithm.digestLength, algorithm.rawValue)
        }
    }
}

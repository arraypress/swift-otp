//
//  ModelTests.swift
//  OTP
//

import XCTest
@testable import OTP

final class ModelTests: XCTestCase {

    func testAlgorithmNamesAsURIsSpellThem() {
        XCTAssertEqual(HashAlgorithm(uriName: "sha1"), .sha1)
        XCTAssertEqual(HashAlgorithm(uriName: "SHA-256"), .sha256)
        XCTAssertEqual(HashAlgorithm(uriName: "Sha512"), .sha512)
        XCTAssertEqual(HashAlgorithm(uriName: "sha_384"), .sha384)
        XCTAssertNil(HashAlgorithm(uriName: "md5"))
        XCTAssertNil(HashAlgorithm(uriName: ""))
        XCTAssertEqual(HashAlgorithm.allCases.map(\.rawValue), ["SHA1", "SHA256", "SHA384", "SHA512"])
    }

    func testEverythingRoundTripsThroughJSON() throws {
        for algorithm in HashAlgorithm.allCases {
            XCTAssertEqual(try JSONDecoder().decode(HashAlgorithm.self, from: JSONEncoder().encode(algorithm)), algorithm)
        }
        for type in OTPType.allCases {
            XCTAssertEqual(try JSONDecoder().decode(OTPType.self, from: JSONEncoder().encode(type)), type)
        }
        let signature = try HMAC.sign("m", key: "k")
        XCTAssertEqual(try JSONDecoder().decode(Signature.self, from: JSONEncoder().encode(signature)), signature)
        let uri = try OTPAuthURI(parsing: "otpauth://hotp/Ex:a?secret=JBSWY3DPEHPK3PXP&counter=3&digits=7&algorithm=SHA512")
        XCTAssertEqual(try JSONDecoder().decode(OTPAuthURI.self, from: JSONEncoder().encode(uri)), uri)
    }

    func testEveryErrorHasADescription() {
        let errors: [OTPError] = [
            .emptySecret, .badDigits(4), .badPeriod(0), .dateBeforeEpoch(Date(timeIntervalSince1970: -1)),
            .badBase32("1"), .badHex("zz"), .badBase64("!"), .badURI("x"), .missingSecret, .missingCounter,
            .badParameter(name: "digits", value: "six"),
        ]
        for error in errors {
            XCTAssertFalse(error.localizedDescription.isEmpty, "\(error)")
            XCTAssertFalse(error.localizedDescription.contains("OTPError"), "\(error)")
        }
        XCTAssertTrue(OTPError.badDigits(4).localizedDescription.contains("6, 7 or 8"))
        XCTAssertTrue(OTPError.missingCounter.localizedDescription.contains("counter"))
    }
}

//
//  Base32Tests.swift
//  OTP
//
//  RFC 4648 section 10's vectors, and the ways a person mangles a secret.
//

import XCTest
@testable import OTP

final class Base32Tests: XCTestCase {

    private let vectors: [(String, String)] = [
        ("", ""), ("f", "MY======"), ("fo", "MZXQ===="), ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI======"),
    ]

    func testTheRFC4648Vectors() throws {
        for (plain, encoded) in vectors {
            XCTAssertEqual(Base32.encode(Data(plain.utf8)), encoded, plain)
            XCTAssertEqual(try Base32.decode(encoded), Data(plain.utf8), encoded)
        }
    }

    func testEncodingWithoutPadding() {
        XCTAssertEqual(Base32.encode(Data("f".utf8), padding: false), "MY")
        XCTAssertEqual(Base32.encode(Data("foobar".utf8), padding: false), "MZXW6YTBOI")
        XCTAssertEqual(Base32.encode(Data(), padding: false), "")
    }

    func testDecodingForgivesWhatAppsForgive() throws {
        let expected = Data("foobar".utf8)
        XCTAssertEqual(try Base32.decode("mzxw6ytboi"), expected, "lowercase")
        XCTAssertEqual(try Base32.decode("MZXW 6YTB OI"), expected, "spaces")
        XCTAssertEqual(try Base32.decode("MZXW-6YTB-OI"), expected, "dashes")
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI"), expected, "no padding")
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI======"), expected, "padding")
        XCTAssertEqual(try Base32.decode(""), Data())
        XCTAssertEqual(try Base32.decode("===="), Data())
    }

    func testAnInvalidCharacterIsNamed() {
        XCTAssertThrowsError(try Base32.decode("MZXW1")) { error in
            XCTAssertEqual(error as? OTPError, .badBase32("1"))
            XCTAssertTrue(error.localizedDescription.contains("A–Z and 2–7"))
        }
        XCTAssertThrowsError(try Base32.decode("MZX0")) { XCTAssertEqual($0 as? OTPError, .badBase32("0")) }
        XCTAssertThrowsError(try Base32.decode("MZX!")) { XCTAssertEqual($0 as? OTPError, .badBase32("!")) }
        XCTAssertThrowsError(try Base32.decode("MZXé"))
    }

    func testEveryByteValueRoundTrips() throws {
        let all = Data((0...255).map { UInt8($0) })
        XCTAssertEqual(try Base32.decode(Base32.encode(all)), all)
        for length in 1...40 {
            let data = Data((0..<length).map { UInt8(($0 * 37) & 0xff) })
            XCTAssertEqual(try Base32.decode(Base32.encode(data, padding: false)), data, "\(length)")
        }
    }

    func testAnAuthenticatorSecret() throws {
        // The secret Google's key-URI documentation uses, in the form apps show it.
        let decoded = try Base32.decode("JBSW Y3DP EHPK 3PXP")
        XCTAssertEqual(decoded.count, 10)
        XCTAssertEqual(Array(decoded.prefix(6)), Array("Hello!".utf8))
        XCTAssertEqual(Array(decoded.suffix(4)), [0xde, 0xad, 0xbe, 0xef])
    }
}

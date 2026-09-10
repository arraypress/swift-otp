//
//  HOTPTests.swift
//  OTP
//
//  RFC 4226 Appendix D, and the edges around it.
//

import XCTest
@testable import OTP

final class HOTPTests: XCTestCase {

    func testTheRFC4226Vectors() throws {
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        for (counter, code) in expected.enumerated() {
            XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: UInt64(counter)), code, "counter \(counter)")
        }
    }

    func testTheRFC4226IntermediateValues() throws {
        // Appendix D also lists the HMAC and the truncated number for counter 0.
        let mac = HMACComputation.mac(HOTPComputation.counterBytes(0), key: Fixtures.sha1Secret, algorithm: .sha1)
        XCTAssertEqual(Rendering.hex(mac), "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")
        XCTAssertEqual(HOTPComputation.truncate(mac, digits: 10), 1284755224)
        XCTAssertEqual(HOTPComputation.truncate(mac, digits: 6), 755224)
    }

    func testMoreDigitsKeepTheirLeadingZeros() throws {
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 0, digits: 8), "84755224")
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 0, digits: 7), "4755224")
        XCTAssertEqual(HOTPComputation.format(7081804, digits: 8), "07081804")
        XCTAssertEqual(HOTPComputation.format(0, digits: 6), "000000")
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 0, digits: 6).count, 6)
    }

    func testOtherHashesWork() throws {
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha256Secret, counter: 1, algorithm: .sha256).count, 6)
        XCTAssertNotEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 1, algorithm: .sha256),
                          try HOTP.code(secret: Fixtures.sha1Secret, counter: 1, algorithm: .sha1))
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha512Secret, counter: 1, algorithm: .sha512).count, 6)
    }

    func testTheCounterIsEightBigEndianBytes() {
        XCTAssertEqual(Array(HOTPComputation.counterBytes(0)), [0, 0, 0, 0, 0, 0, 0, 0])
        XCTAssertEqual(Array(HOTPComputation.counterBytes(1)), [0, 0, 0, 0, 0, 0, 0, 1])
        XCTAssertEqual(Array(HOTPComputation.counterBytes(0x0102030405060708)), [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(Array(HOTPComputation.counterBytes(.max)), Array(repeating: 0xff, count: 8))
    }

    func testTheLargestCounterStillProducesACode() throws {
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: .max).count, 6)
    }

    func testRefusals() {
        XCTAssertThrowsError(try HOTP.code(secret: Data(), counter: 0)) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        for digits in [0, 1, 5, 9, 10, -1] {
            XCTAssertThrowsError(try HOTP.code(secret: Fixtures.sha1Secret, counter: 0, digits: digits)) {
                XCTAssertEqual($0 as? OTPError, .badDigits(digits))
            }
        }
    }
}

//
//  TOTPTests.swift
//  OTP
//
//  RFC 6238 Appendix B: eight digits, three hashes, six moments.
//

import XCTest
@testable import OTP

final class TOTPTests: XCTestCase {

    private let vectors: [(TimeInterval, String, String, String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ]

    func testTheRFC6238Vectors() throws {
        for (seconds, sha1, sha256, sha512) in vectors {
            let at = Date(timeIntervalSince1970: seconds)
            XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at, digits: 8), sha1, "sha1 @\(seconds)")
            XCTAssertEqual(try TOTP.code(secret: Fixtures.sha256Secret, at: at, digits: 8, algorithm: .sha256), sha256, "sha256 @\(seconds)")
            XCTAssertEqual(try TOTP.code(secret: Fixtures.sha512Secret, at: at, digits: 8, algorithm: .sha512), sha512, "sha512 @\(seconds)")
        }
    }

    func testSixDigitsAreTheLastSixOfEight() throws {
        let at = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at), "287082")
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at, digits: 7), "4287082")
    }

    func testTheStepIsWholePeriods() throws {
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 0), period: 30), 0)
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 29.999), period: 30), 0)
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 30), period: 30), 1)
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 59), period: 30), 1)
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 1_111_111_109), period: 30), 37_037_036)
        XCTAssertEqual(try TimeSteps.step(at: Date(timeIntervalSince1970: 120), period: 60), 2)
    }

    func testAnotherPeriodChangesTheStepNotTheArithmetic() throws {
        let at = Date(timeIntervalSince1970: 1_111_111_109)
        // At a 60-second period the step is 18_518_518, so the code is HOTP at that counter.
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at, period: 60),
                       try HOTP.code(secret: Fixtures.sha1Secret, counter: 18_518_518))
        XCTAssertNotEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at, period: 60),
                          try TOTP.code(secret: Fixtures.sha1Secret, at: at, period: 30))
    }

    func testRemainingSecondsAtTheBoundary() throws {
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 0)), 30)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 30)), 30)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 29)), 1)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 29.5)), 1)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 1)), 29)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 61), period: 60), 59)
    }

    func testValidationAcceptsTheNeighbouringStepsAndNotBeyond() throws {
        let secret = Fixtures.sha1Secret
        let now = Date(timeIntervalSince1970: 1_234_567_890)
        let current = try TOTP.code(secret: secret, at: now)
        let previous = try TOTP.code(secret: secret, at: now.addingTimeInterval(-30))
        let next = try TOTP.code(secret: secret, at: now.addingTimeInterval(30))
        let twoBack = try TOTP.code(secret: secret, at: now.addingTimeInterval(-60))
        let twoAhead = try TOTP.code(secret: secret, at: now.addingTimeInterval(60))

        XCTAssertTrue(try TOTP.validate(current, secret: secret, at: now))
        XCTAssertTrue(try TOTP.validate(previous, secret: secret, at: now))
        XCTAssertTrue(try TOTP.validate(next, secret: secret, at: now))
        XCTAssertFalse(try TOTP.validate(twoBack, secret: secret, at: now))
        XCTAssertFalse(try TOTP.validate(twoAhead, secret: secret, at: now))
        XCTAssertTrue(try TOTP.validate(twoAhead, secret: secret, at: now, window: 2))
        XCTAssertFalse(try TOTP.validate(previous, secret: secret, at: now, window: 0))
        XCTAssertTrue(try TOTP.validate(current, secret: secret, at: now, window: 0))
    }

    func testValidationIgnoresTheSpacesAppsDisplay() throws {
        let now = Date(timeIntervalSince1970: 1_234_567_890)
        let code = try TOTP.code(secret: Fixtures.sha1Secret, at: now)
        let spaced = String(code.prefix(3)) + " " + String(code.suffix(3))
        XCTAssertTrue(try TOTP.validate(spaced, secret: Fixtures.sha1Secret, at: now))
    }

    func testValidationRejectsTheWrongShape() throws {
        let now = Date(timeIntervalSince1970: 1_234_567_890)
        XCTAssertFalse(try TOTP.validate("", secret: Fixtures.sha1Secret, at: now))
        XCTAssertFalse(try TOTP.validate("12345", secret: Fixtures.sha1Secret, at: now))
        XCTAssertFalse(try TOTP.validate("1234567", secret: Fixtures.sha1Secret, at: now))
        XCTAssertFalse(try TOTP.validate("abcdef", secret: Fixtures.sha1Secret, at: now))
    }

    func testCandidateStepsNeverGoBelowZero() {
        XCTAssertEqual(TimeSteps.candidates(around: 0, window: 1), [0, 1])
        XCTAssertEqual(TimeSteps.candidates(around: 1, window: 1), [1, 0, 2])
        XCTAssertEqual(TimeSteps.candidates(around: 5, window: 2), [5, 4, 6, 3, 7])
        XCTAssertEqual(TimeSteps.candidates(around: 5, window: 0), [5])
    }

    func testRefusals() {
        let now = Date(timeIntervalSince1970: 1_234_567_890)
        XCTAssertThrowsError(try TOTP.code(secret: Fixtures.sha1Secret, at: now, period: 0)) { XCTAssertEqual($0 as? OTPError, .badPeriod(0)) }
        XCTAssertThrowsError(try TOTP.code(secret: Fixtures.sha1Secret, at: now, period: -30))
        XCTAssertThrowsError(try TOTP.code(secret: Fixtures.sha1Secret, at: now, period: .infinity))
        XCTAssertThrowsError(try TOTP.code(secret: Fixtures.sha1Secret, at: Date(timeIntervalSince1970: -1))) { error in
            XCTAssertEqual(error as? OTPError, .dateBeforeEpoch(Date(timeIntervalSince1970: -1)))
            XCTAssertTrue(error.localizedDescription.contains("1970"))
        }
        XCTAssertThrowsError(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: -1)))
        XCTAssertThrowsError(try TOTP.remainingSeconds(at: now, period: 0))
        XCTAssertThrowsError(try TOTP.code(secret: Data(), at: now)) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        XCTAssertThrowsError(try TOTP.validate("123456", secret: Fixtures.sha1Secret, at: now, digits: 4))
    }

    func testConstantTimeEqualityOnPlainStrings() {
        XCTAssertTrue(ConstantTime.equal("123456", "123456"))
        XCTAssertFalse(ConstantTime.equal("123456", "123457"))
        XCTAssertFalse(ConstantTime.equal("023456", "123456"))
        XCTAssertFalse(ConstantTime.equal("12345", "123456"))
        XCTAssertTrue(ConstantTime.equal("", ""))
    }
}

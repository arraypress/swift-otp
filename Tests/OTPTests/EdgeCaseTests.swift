//
//  EdgeCaseTests.swift
//  OTP
//
//  One question per test, at the edges: lengths, boundaries, the largest
//  values, and each RFC case on its own so a failure names itself.
//

import XCTest
@testable import OTP

final class Base32EdgeTests: XCTestCase {

    func testPaddingLengthsForOneToFiveBytes() {
        // 5 bytes fill 8 characters exactly; anything short pads to the block.
        XCTAssertEqual(Base32.encode(Data([1])).count, 8)
        XCTAssertEqual(Base32.encode(Data([1, 2])).count, 8)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3])).count, 8)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3, 4])).count, 8)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3, 4, 5])).count, 8)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3, 4, 5, 6])).count, 16)
        XCTAssertFalse(Base32.encode(Data([1, 2, 3, 4, 5])).contains("="))
    }

    func testUnpaddedLengthsMatchTheRFCsTable() {
        XCTAssertEqual(Base32.encode(Data([1]), padding: false).count, 2)
        XCTAssertEqual(Base32.encode(Data([1, 2]), padding: false).count, 4)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3]), padding: false).count, 5)
        XCTAssertEqual(Base32.encode(Data([1, 2, 3, 4]), padding: false).count, 7)
    }

    func testAllZeroBytesAreAllAs() {
        XCTAssertEqual(Base32.encode(Data([0, 0, 0, 0, 0])), "AAAAAAAA")
        XCTAssertEqual(Base32.encode(Data([0xff, 0xff, 0xff, 0xff, 0xff])), "77777777")
    }

    func testPaddingInTheMiddleIsIgnoredNotRejected() throws {
        // Apps do not produce this; a person pasting two fragments might.
        XCTAssertEqual(try Base32.decode("MY======MY======"), Data("ff".utf8))
    }

    func testTheAlphabetHasThirtyTwoDistinctCharacters() {
        XCTAssertEqual(Set(Base32Coding.alphabet).count, 32)
        XCTAssertEqual(Base32Coding.values.count, 32)
        XCTAssertNil(Base32Coding.values["0"])
        XCTAssertNil(Base32Coding.values["1"])
        XCTAssertNil(Base32Coding.values["8"])
    }
}

final class HOTPEdgeTests: XCTestCase {

    func testEachDigitCountIsAcceptedOnItsOwn() throws {
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 3, digits: 6), "969429")
        // RFC 4226 Appendix D gives counter 3's decimal as 1226969429.
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 3, digits: 7), "6969429")
        XCTAssertEqual(try HOTP.code(secret: Fixtures.sha1Secret, counter: 3, digits: 8), "26969429")
    }

    func testAOneByteSecretWorks() throws {
        XCTAssertEqual(try HOTP.code(secret: Data([0x01]), counter: 0).count, 6)
    }

    func testAVeryLongSecretWorks() throws {
        XCTAssertEqual(try HOTP.code(secret: Data(repeating: 0x42, count: 4096), counter: 0).count, 6)
    }

    func testConsecutiveCountersDiffer() throws {
        let codes = try (0..<50).map { try HOTP.code(secret: Fixtures.sha1Secret, counter: UInt64($0)) }
        XCTAssertGreaterThan(Set(codes).count, 45, "fifty counters should almost never collide")
    }

    func testTruncationPicksTheOffsetFromTheLastNibble() {
        // A hand-built MAC: last byte 0x03 → offset 3 → bytes 3…6 → 0x00000001.
        var mac = Data(repeating: 0, count: 20)
        mac[6] = 0x01
        mac[19] = 0x03
        XCTAssertEqual(HOTPComputation.truncate(mac, digits: 6), 1)
        // The top bit of the first picked byte is cleared: 0xff000001 reads as 0x7f000001.
        mac[3] = 0xff
        XCTAssertEqual(HOTPComputation.truncate(mac, digits: 10), 0x7f000001)
    }

    func testFormatNeverTruncates() {
        XCTAssertEqual(HOTPComputation.format(123, digits: 6), "000123")
        XCTAssertEqual(HOTPComputation.format(99_999_999, digits: 8), "99999999")
    }
}

final class TOTPEdgeTests: XCTestCase {

    func testTheEpochIsStepZero() throws {
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: Date(timeIntervalSince1970: 0)),
                       try HOTP.code(secret: Fixtures.sha1Secret, counter: 0))
    }

    func testTheCodeIsStableWithinAPeriod() throws {
        let start = Date(timeIntervalSince1970: 1_234_567_890)   // step boundary: 1234567890 / 30 = 41152263
        let code = try TOTP.code(secret: Fixtures.sha1Secret, at: start)
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: start.addingTimeInterval(29.99)), code)
        XCTAssertNotEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: start.addingTimeInterval(30)), code)
    }

    func testAOneSecondPeriodChangesEverySecond() throws {
        let at = Date(timeIntervalSince1970: 1000)
        XCTAssertNotEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: at, period: 1),
                          try TOTP.code(secret: Fixtures.sha1Secret, at: at.addingTimeInterval(1), period: 1))
        XCTAssertEqual(try TOTP.remainingSeconds(at: at, period: 1), 1)
    }

    func testANegativeWindowMeansNoWindow() throws {
        let now = Date(timeIntervalSince1970: 1_234_567_890)
        let previous = try TOTP.code(secret: Fixtures.sha1Secret, at: now.addingTimeInterval(-30))
        XCTAssertFalse(try TOTP.validate(previous, secret: Fixtures.sha1Secret, at: now, window: -3))
    }

    func testAFarFutureDateStillHasAStep() throws {
        let far = Date(timeIntervalSince1970: 20_000_000_000)
        XCTAssertEqual(try TimeSteps.step(at: far, period: 30), 666_666_666)
        XCTAssertEqual(try TOTP.code(secret: Fixtures.sha1Secret, at: far, digits: 8), "65353130")
    }

    func testRemainingSecondsRoundsUpToAWholeSecond() throws {
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 0.1)), 30)
        XCTAssertEqual(try TOTP.remainingSeconds(at: Date(timeIntervalSince1970: 28.2)), 2)
    }

    func testValidationWithEightDigitsAndSHA512() throws {
        let at = Date(timeIntervalSince1970: 1_111_111_111)
        XCTAssertTrue(try TOTP.validate("99943326", secret: Fixtures.sha512Secret, at: at, digits: 8, algorithm: .sha512))
        XCTAssertFalse(try TOTP.validate("99943326", secret: Fixtures.sha512Secret, at: at, digits: 8, algorithm: .sha256))
        XCTAssertFalse(try TOTP.validate("999433", secret: Fixtures.sha512Secret, at: at, digits: 8, algorithm: .sha512))
    }
}

final class HMACEdgeTests: XCTestCase {

    func testRFC4231Case1SHA256() throws {
        XCTAssertEqual(try HMAC.sign(Data("Hi There".utf8), key: Fixtures.bytes(0x0b, count: 20)).hex,
                       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }

    func testRFC4231Case2SHA384() throws {
        XCTAssertEqual(try HMAC.sign("what do ya want for nothing?", key: "Jefe", algorithm: .sha384).hex,
                       "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
    }

    func testRFC4231Case3SHA512() throws {
        XCTAssertEqual(try HMAC.sign(Fixtures.bytes(0xdd, count: 50), key: Fixtures.bytes(0xaa, count: 20), algorithm: .sha512).hex,
                       "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")
    }

    func testRFC4231Case4SHA256() throws {
        XCTAssertEqual(try HMAC.sign(Fixtures.bytes(0xcd, count: 50), key: Data((1...25).map { UInt8($0) })).hex,
                       "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
    }

    func testAKeyLongerThanTheBlockIsHashedFirstAsTheRFCSays() throws {
        // RFC 4231 case 6: 131-byte key, "Test Using Larger Than Block-Size Key - Hash Key First".
        XCTAssertEqual(try HMAC.sign(Data("Test Using Larger Than Block-Size Key - Hash Key First".utf8), key: Fixtures.bytes(0xaa, count: 131)).hex,
                       "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    }

    func testTheSameInputsAlwaysGiveTheSameSignature() throws {
        let one = try HMAC.sign("m", key: "k"), two = try HMAC.sign("m", key: "k")
        XCTAssertEqual(one, two)
        XCTAssertEqual(one.hex, two.hex)
    }

    func testSHA1SignaturesVerifyToo() throws {
        let signature = try HMAC.sign("Hi There", key: "k", algorithm: .sha1)
        XCTAssertEqual(signature.data.count, 20)
        XCTAssertTrue(try HMAC.verify(signature, message: Data("Hi There".utf8), key: Data("k".utf8)))
        XCTAssertTrue(try HMAC.verify(hex: signature.hex, message: Data("Hi There".utf8), key: Data("k".utf8), algorithm: .sha1))
        XCTAssertTrue(try HMAC.verify(base64: signature.base64, message: Data("Hi There".utf8), key: Data("k".utf8), algorithm: .sha1))
    }

    func testHexParsingEdges() throws {
        XCTAssertEqual(try Rendering.data(fromHex: "0X00FF"), Data([0x00, 0xff]))
        XCTAssertEqual(try Rendering.data(fromHex: " 0aff "), Data([0x0a, 0xff]))
        XCTAssertThrowsError(try Rendering.data(fromHex: "0x"))
        XCTAssertThrowsError(try Rendering.data(fromHex: "0g"))
        XCTAssertThrowsError(try Rendering.data(fromHex: "abc"))
    }
}

final class URIEdgeTests: XCTestCase {

    func testABuiltURIWithNoIssuerHasNoColon() throws {
        let uri = try OTPAuthURI(type: .totp, account: "alice", secret: try Base32.decode("JBSWY3DPEHPK3PXP"))
        XCTAssertTrue(uri.uri.hasPrefix("otpauth://totp/alice?"))
        XCTAssertFalse(uri.uri.contains("issuer="))
    }

    func testAnIssuerWithACharacterThatNeedsEncodingRoundTrips() throws {
        let uri = try OTPAuthURI(type: .totp, issuer: "A & B/C", account: "x y", secret: try Base32.decode("JBSWY3DPEHPK3PXP"))
        let again = try OTPAuthURI(parsing: uri.uri)
        XCTAssertEqual(again.issuer, "A & B/C")
        XCTAssertEqual(again.account, "x y")
    }

    func testTrailingWhitespaceAndNewlinesAreIgnored() throws {
        let uri = try OTPAuthURI(parsing: "  otpauth://totp/a?secret=JBSWY3DPEHPK3PXP\n")
        XCTAssertEqual(uri.account, "a")
    }

    func testAnUnknownParameterIsIgnored() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fx.test%2Fi.png&foo=bar")
        XCTAssertEqual(uri.digits, 6)
    }

    func testTheLargestCounterIsAccepted() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615")
        XCTAssertEqual(uri.counter, .max)
        XCTAssertEqual(uri.advanced().counter, 0, "wraps rather than traps")
    }

    func testAFractionalPeriodIsKept() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=2.5")
        XCTAssertEqual(uri.period, 2.5)
        XCTAssertTrue(uri.uri.contains("period=2.5"))
    }

    func testTheLabelSplitOnPlainStrings() {
        XCTAssertEqual(URIParsing.split(label: "Issuer:account").issuer, "Issuer")
        XCTAssertEqual(URIParsing.split(label: "Issuer:account").account, "account")
        XCTAssertEqual(URIParsing.split(label: "account").issuer, "")
        XCTAssertEqual(URIParsing.split(label: " Spaced : user ").issuer, "Spaced")
        XCTAssertEqual(URIParsing.split(label: " Spaced : user ").account, "user")
        XCTAssertEqual(URIParsing.split(label: "a:b:c").account, "b:c")
    }
}

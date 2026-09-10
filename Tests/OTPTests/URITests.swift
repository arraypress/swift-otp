//
//  URITests.swift
//  OTP
//
//  Google Authenticator's key URI format, as QR codes carry it.
//

import XCTest
@testable import OTP

final class URITests: XCTestCase {

    func testTheDocumentationExample() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        XCTAssertEqual(uri.type, .totp)
        XCTAssertEqual(uri.issuer, "Example")
        XCTAssertEqual(uri.account, "alice@google.com")
        XCTAssertEqual(uri.secret, try Base32.decode("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(uri.digits, 6)
        XCTAssertEqual(uri.period, 30)
        XCTAssertEqual(uri.algorithm, .sha1)
        XCTAssertNil(uri.counter)
    }

    func testEveryParameterIsRead() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
        XCTAssertEqual(uri.issuer, "ACME Co")
        XCTAssertEqual(uri.account, "john.doe@email.com")
        XCTAssertEqual(uri.algorithm, .sha256)
        XCTAssertEqual(uri.digits, 8)
        XCTAssertEqual(uri.period, 60)
    }

    func testAnHOTPURICarriesItsCounter() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=42")
        XCTAssertEqual(uri.type, .hotp)
        XCTAssertEqual(uri.counter, 42)
        XCTAssertEqual(try uri.code(), try HOTP.code(secret: try Base32.decode("JBSWY3DPEHPK3PXP"), counter: 42))
        XCTAssertEqual(uri.advanced().counter, 43)
        XCTAssertEqual(uri.advanced().advanced().counter, 44)
    }

    func testTheIssuerParameterWinsOverTheLabel() throws {
        let both = try OTPAuthURI(parsing: "otpauth://totp/OldName:alice?secret=JBSWY3DPEHPK3PXP&issuer=NewName")
        XCTAssertEqual(both.issuer, "NewName")
        let labelOnly = try OTPAuthURI(parsing: "otpauth://totp/OnlyLabel:alice?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(labelOnly.issuer, "OnlyLabel")
        let parameterOnly = try OTPAuthURI(parsing: "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=OnlyParam")
        XCTAssertEqual(parameterOnly.issuer, "OnlyParam")
        XCTAssertEqual(parameterOnly.account, "alice")
        let none = try OTPAuthURI(parsing: "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(none.issuer, "")
    }

    func testLabelsArePercentDecodedAndSplitOnTheFirstColon() throws {
        let encoded = try OTPAuthURI(parsing: "otpauth://totp/Big%20Corp%3Auser%3Aname%40host?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(encoded.issuer, "Big Corp")
        XCTAssertEqual(encoded.account, "user:name@host")
        let spaced = try OTPAuthURI(parsing: "otpauth://totp/Corp:%20alice%20?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(spaced.account, "alice")
    }

    func testParametersAreForgivingWhereAppsAre() throws {
        let lower = try OTPAuthURI(parsing: "otpauth://TOTP/a?SECRET=jbswy3dpehpk3pxp&Algorithm=sha-512&Digits=7")
        XCTAssertEqual(lower.type, .totp)
        XCTAssertEqual(lower.algorithm, .sha512)
        XCTAssertEqual(lower.digits, 7)
        XCTAssertEqual(lower.secret, try Base32.decode("JBSWY3DPEHPK3PXP"))
        let padded = try OTPAuthURI(parsing: "otpauth://totp/a?secret=MZXW6YTBOI%3D%3D%3D%3D%3D%3D")
        XCTAssertEqual(padded.secret, Data("foobar".utf8))
    }

    func testRefusals() {
        func refused(_ text: String, _ expected: OTPError, line: UInt = #line) {
            XCTAssertThrowsError(try OTPAuthURI(parsing: text), text, line: line) { XCTAssertEqual($0 as? OTPError, expected, text, line: line) }
        }
        refused("https://totp/a?secret=JBSWY3DPEHPK3PXP", .badURI("https://totp/a?secret=JBSWY3DPEHPK3PXP"))
        refused("otpauth://sms/a?secret=JBSWY3DPEHPK3PXP", .badURI("otpauth://sms/a?secret=JBSWY3DPEHPK3PXP"))
        refused("", .badURI(""))
        refused("not a uri at all", .badURI("not a uri at all"))
        refused("otpauth://totp/a", .missingSecret)
        refused("otpauth://totp/a?secret=", .missingSecret)
        refused("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP", .missingCounter)
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=six", .badParameter(name: "digits", value: "six"))
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=4", .badDigits(4))
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0", .badPeriod(0))
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=soon", .badParameter(name: "period", value: "soon"))
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=md5", .badParameter(name: "algorithm", value: "md5"))
        refused("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=-1", .badParameter(name: "counter", value: "-1"))
        refused("otpauth://totp/a?secret=JBSWY3DPEHPK3PX1", .badBase32("1"))
    }

    func testBuildingWritesEverythingOut() throws {
        let secret = try Base32.decode("JBSWY3DPEHPK3PXP")
        let totp = try OTPAuthURI(type: .totp, issuer: "ACME Co", account: "john.doe@email.com", secret: secret, digits: 8, period: 60, algorithm: .sha256)
        XCTAssertEqual(totp.uri, "otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
        let hotp = try OTPAuthURI(type: .hotp, account: "alice", secret: secret, counter: 7)
        XCTAssertEqual(hotp.uri, "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=7")
        XCTAssertEqual(URIBuilding.formatted(30), "30")
        XCTAssertEqual(URIBuilding.formatted(2.5), "2.5")
    }

    func testRoundTrips() throws {
        let originals = [
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
            "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=42",
            "otpauth://totp/Big%20Corp%3Auser%3Aname%40host?secret=JBSWY3DPEHPK3PXP",
        ]
        for original in originals {
            let parsed = try OTPAuthURI(parsing: original)
            let again = try OTPAuthURI(parsing: parsed.uri)
            XCTAssertEqual(again, parsed, original)
        }
    }

    func testTheModelIsCheckedOnTheWayIn() throws {
        let secret = try Base32.decode("JBSWY3DPEHPK3PXP")
        XCTAssertThrowsError(try OTPAuthURI(type: .totp, account: "a", secret: Data())) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        XCTAssertThrowsError(try OTPAuthURI(type: .totp, account: "a", secret: secret, digits: 9)) { XCTAssertEqual($0 as? OTPError, .badDigits(9)) }
        XCTAssertThrowsError(try OTPAuthURI(type: .totp, account: "a", secret: secret, period: -1))
        XCTAssertThrowsError(try OTPAuthURI(type: .hotp, account: "a", secret: secret)) { XCTAssertEqual($0 as? OTPError, .missingCounter) }
        let totpWithCounter = try OTPAuthURI(type: .totp, account: "a", secret: secret, counter: 5)
        XCTAssertNil(totpWithCounter.counter, "a TOTP URI drops a counter it cannot use")
        XCTAssertEqual(totpWithCounter.advanced(), totpWithCounter)
    }

    func testTheCodeFromAURIIsTheCodeFromItsParts() throws {
        let uri = try OTPAuthURI(parsing: "otpauth://totp/a?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8")
        let at = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(try uri.code(at: at), "94287082")
        XCTAssertThrowsError(try uri.code(at: Date(timeIntervalSince1970: -5)))
    }
}

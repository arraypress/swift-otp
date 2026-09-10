//
//  HOTPComputation.swift
//  OTP
//
//  RFC 4226 section 5.3: the counter as bytes, and dynamic truncation.
//

import Foundation

/// The arithmetic of RFC 4226, on plain bytes and integers.
enum HOTPComputation {

    /// The counter as eight big-endian bytes — the message the MAC signs.
    static func counterBytes(_ counter: UInt64) -> Data {
        var value = counter.bigEndian
        return Data(bytes: &value, count: 8)
    }

    /// Dynamic truncation: the low nibble of the last byte picks an offset,
    /// the four bytes there (top bit cleared) are a 31-bit number, and the
    /// code is that number modulo 10^digits.
    static func truncate(_ mac: Data, digits: Int) -> Int {
        let bytes = Array(mac)
        let offset = Int(bytes[bytes.count - 1] & 0x0f)
        let binary = (Int(bytes[offset] & 0x7f) << 24)
            | (Int(bytes[offset + 1]) << 16)
            | (Int(bytes[offset + 2]) << 8)
            | Int(bytes[offset + 3])
        return binary % Int(pow(10, Double(digits)))
    }

    /// Zero-padded to `digits` — 007081804 is a different code from 7081804.
    static func format(_ code: Int, digits: Int) -> String {
        let text = String(code)
        return String(repeating: "0", count: max(0, digits - text.count)) + text
    }
}

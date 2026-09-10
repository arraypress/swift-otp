//
//  ConstantTime.swift
//  OTP
//

import Foundation

/// Comparison that takes the same time whether the first byte or the last
/// one differs.
enum ConstantTime {

    /// Equal length and equal bytes, checked without an early exit. The length
    /// is not a secret — a typed code is six digits either way — so a length
    /// mismatch returns at once.
    static func equal(_ a: String, _ b: String) -> Bool {
        let left = Array(a.utf8), right = Array(b.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

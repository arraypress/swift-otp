//
//  TimeSteps.swift
//  OTP
//
//  RFC 6238: time as a counter.
//

import Foundation

/// Seconds since 1970 into whole periods, and back.
enum TimeSteps {

    /// The number of whole periods since the epoch.
    static func step(at date: Date, period: TimeInterval) throws -> UInt64 {
        let seconds = date.timeIntervalSince1970
        guard seconds >= 0 else { throw OTPError.dateBeforeEpoch(date) }
        return UInt64((seconds / period).rounded(.down))
    }

    /// Seconds left in the current period, counting the boundary as a full period.
    static func remainingSeconds(at date: Date, period: TimeInterval) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds >= 0 else { throw OTPError.dateBeforeEpoch(date) }
        let elapsed = seconds.truncatingRemainder(dividingBy: period)
        return Int((period - elapsed).rounded(.up))
    }

    /// The steps to try for a window: the current one, then each neighbour
    /// out to `window` on both sides, never below zero.
    static func candidates(around step: UInt64, window: Int) -> [UInt64] {
        var steps: [UInt64] = [step]
        for offset in 1...max(1, window) where window >= 1 {
            let distance = UInt64(offset)
            if step >= distance { steps.append(step - distance) }
            steps.append(step &+ distance)
        }
        return steps
    }
}

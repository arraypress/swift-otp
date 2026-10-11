// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "swift-otp",
    platforms: [
        .macOS(.v14), .iOS(.v16), .tvOS(.v16), .watchOS(.v9), .visionOS(.v1),
    ],
    products: [
        .library(name: "OTP", targets: ["OTP"]),
    ],
    targets: [
        .target(name: "OTP"),
        .testTarget(name: "OTPTests", dependencies: ["OTP"]),
    ]
)

// Swift 7's import rule, today: a file must import every module whose members
// it uses, rather than leaning on another file's imports.
for target in package.targets where target.type != .system && target.type != .binary && target.type != .plugin {
    target.swiftSettings = (target.swiftSettings ?? []) + [.enableUpcomingFeature("MemberImportVisibility")]
}

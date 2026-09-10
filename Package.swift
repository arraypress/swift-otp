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

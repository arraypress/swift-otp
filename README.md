# Swift OTP

The six-digit codes an authenticator shows, and the keyed hashes that sign and verify API requests — as typed values, with the RFCs' own test vectors, on any Apple platform.

```swift
import OTP

// The QR code a service showed you, as an authenticator reads it.
let account = try OTPAuthURI(parsing: "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
try account.code()                                     // "492039" — the code right now
try TOTP.remainingSeconds()                            // 17

// A webhook the way GitHub or Stripe sends it.
let body = Data(request.body)
try HMAC.verify(hex: headerWithoutPrefix, message: body, key: Data(secret.utf8))   // true, in constant time

// Signing your own request.
try HMAC.sign("timestamp=1700000000&symbol=BTCUSDT", key: apiSecret).hex
```

## Why

| Question | The wrong answer, and why it is tempting |
|---|---|
| Why does my TOTP fail every RFC 6238 vector? | The SHA-256 and SHA-512 secrets are not the SHA-1 secret. The RFC repeats `12345678901234567890` to 32 and 64 bytes and says so in a footnote almost nobody reads. |
| Why is the code wrong for this one account? | The secret was pasted with spaces, in lowercase, or without its `=` padding. Authenticator apps forgive all three, so the decoder here does too. |
| Is `signature == expected` fine? | No. `==` stops at the first wrong byte, so the time it takes says how many leading bytes were right. Verification here goes through CryptoKit's constant-time check. |
| The code was right a second ago. | A phone's clock and a server's are never exactly aligned. Validation accepts the step either side, which is the allowance every service makes. |
| Which issuer, the label's or the parameter's? | The parameter. Google's key-URI format says so, and that is what apps do when the two disagree. |

## Installation

```swift
.package(url: "https://github.com/arraypress/swift-otp.git", from: "0.1.0")
```

CryptoKit and Foundation. Every Apple platform, macOS 14+.

## A code from a secret

```swift
let secret = try Base32.decode("JBSW Y3DP EHPK 3PXP")     // spaces, case and padding forgiven
try TOTP.code(secret: secret)                             // now, 30 seconds, 6 digits, SHA-1
try TOTP.code(secret: secret, at: date, period: 60, digits: 8, algorithm: .sha256)
try HOTP.code(secret: secret, counter: 7)                 // counter-based
```

TOTP is HOTP with the counter set to the number of whole periods since 1970. Codes keep
their leading zeros — `007081804` is a different code from `7081804` — and are 6, 7 or 8
digits, which is what RFC 4226 asks for and every authenticator produces.

## Checking a code somebody typed

```swift
try TOTP.validate("492 039", secret: secret)              // the previous and next step count too
try TOTP.validate(code, secret: secret, window: 0)        // strict: this step only
```

Spaces are ignored because that is how apps display the number. The comparison is
constant-time, so a wrong guess takes as long as a right one.

## The QR code

```swift
let uri = try OTPAuthURI(parsing: "otpauth://totp/ACME%20Co:john@example.com?secret=…&issuer=ACME%20Co&digits=8&period=60&algorithm=SHA256")
uri.issuer, uri.account, uri.digits, uri.period, uri.algorithm
try uri.code()                                            // for HOTP, at its counter
uri.advanced()                                            // HOTP: the state to keep after a code is used
uri.uri                                                   // back to text, every parameter written out
```

Digits, period and algorithm fall back to 6, 30 and SHA-1 when the URI omits them. An
HOTP URI without a counter is refused, because it cannot make a code.

## Signing and verifying

```swift
let signature = try HMAC.sign(payload, key: secret)       // SHA-256 unless you say otherwise
signature.hex                                             // GitHub's and Stripe's form
signature.base64                                          // Shopify's form

try HMAC.verify(hex: hexFromHeader, message: payload, key: secret)
try HMAC.verify(base64: base64FromHeader, message: payload, key: secret)
try HMAC.verify(signature, message: payload, key: secret)
```

A signature carries its algorithm, because the same key and message give a different
result under each hash and the header says which one was used. An empty key is refused.

## Tested

80 tests. Every vector the RFCs publish: RFC 4648's seven Base32 strings, RFC 4226's
ten HOTP counters and their intermediate HMAC, RFC 6238's six moments under SHA-1,
SHA-256 and SHA-512, RFC 4231's cases 1–4 and 6 and RFC 2202's first two. Around them:
the step boundary, the drift window at ±1 and ±2, a one-byte tamper at each end of a
signature, every URI refusal by name, round trips through text and JSON.

## Licence

MIT.

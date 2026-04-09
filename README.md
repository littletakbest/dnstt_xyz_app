# Android ARM64 Tunnel Client

Android-only Flutter app for DNS tunneling with two transports:
- `DNSTT` for KCP + Noise over DNS
- `Slipstream` for QUIC-over-DNS

## Status

This repository is now scoped to:
- Android only
- `arm64-v8a` only

Desktop targets and desktop release artifacts are no longer part of this repo.

## Build

### Prerequisites

- Flutter SDK 3.x+
- Android SDK / NDK
- Java 17
- Go 1.21+
- `gomobile`
- Rust + `cargo-ndk` for Android Slipstream builds

### Android release build

```bash
flutter pub get
flutter build apk --release --target-platform android-arm64
```

Output:
- `build/app/outputs/flutter-apk/app-arm64-v8a-release.apk`

### Android App Bundle

```bash
flutter build appbundle --release
```

The Gradle config is locked to `arm64-v8a`, so generated Android artifacts stay ARM64-only.

## Rebuilding Native Components

### Rebuild `dnstt.aar` for Android ARM64

```bash
cd go_src
gomobile bind -v -androidapi 21 -target=android/arm64 -o dnstt.aar ./mobile
cp dnstt.aar ../android/app/libs/
```

### Rebuild Slipstream Android binary

```bash
./scripts/build_slipstream_android.sh
```

## Project Structure

```text
android/                 Android app and native Kotlin services
go_src/                  Go dnstt source
lib/                     Flutter UI and app logic
vendor/slipstream-rust/  Slipstream source
scripts/                 Android/native helper scripts
```

## Notes For Rebranding

The repo has been narrowed to Android ARM64 so packaging is simpler before a rename.
The current package id / method channels / Kotlin namespace still use the old identifiers and can be changed cleanly once the new brand name is decided.

## License

The app uses the bundled `dnstt` source. See `go_src/COPYING` and the other upstream licenses included in the repository.

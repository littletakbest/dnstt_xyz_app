# LittleDNST

Android-only DNS tunneling with two transports:
- `DNSTT` for KCP + Noise over DNS
- `Slipstream` for QUIC-over-DNS


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


## License

The app uses the bundled `dnstt` source. See `go_src/COPYING` and the other upstream licenses included in the repository.

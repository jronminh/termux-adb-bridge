#!/data/data/com.termux/files/usr/bin/bash
# Builds adbwifi-helper.apk entirely inside Termux, no Gradle/Android
# Studio required. Needs: pkg install openjdk-21 aapt aapt2 d8 apksigner
#
# Uses a real .class-based android.jar stub (the device's own
# /system/framework/framework.jar is raw DEX, unusable by javac) from
# https://github.com/Reginer/aosp-android-jar - pick the android-XX
# directory matching your device's API level (`getprop
# ro.build.version.sdk`), or just use a recent one; MainActivity.java and
# EnableReceiver.java only use long-stable APIs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$(dirname "$HERE")/out}"
BUILD="$HERE/build"
ANDROID_JAR="${ANDROID_JAR:-$HERE/android.jar}"
KEYSTORE="$HERE/debug.keystore"
mkdir -p "$OUT_DIR"

if [ ! -f "$ANDROID_JAR" ]; then
    echo "Missing $ANDROID_JAR" >&2
    echo "Download one matching your device's API level, e.g.:" >&2
    echo "  curl -sL -o '$ANDROID_JAR' \\" >&2
    echo "    https://raw.githubusercontent.com/Reginer/aosp-android-jar/main/android-34/android.jar" >&2
    exit 1
fi

if [ ! -f "$KEYSTORE" ]; then
    echo "Generating a throwaway debug keystore at $KEYSTORE ..."
    keytool -genkeypair -v -keystore "$KEYSTORE" -alias debugkey \
        -storepass android -keypass android -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=AdbWifiHelper"
fi

rm -rf "$BUILD"
mkdir -p "$BUILD/obj"
cd "$HERE"

echo "Compiling Java sources..."
javac -cp "$ANDROID_JAR" -d "$BUILD/obj" \
    src/local/adbwifi/helper/EnableReceiver.java

echo "Converting to dex..."
d8 --output "$BUILD" \
    "$BUILD/obj/local/adbwifi/helper/EnableReceiver.class"

echo "Packaging unsigned APK..."
aapt package -f -M AndroidManifest.xml -I "$ANDROID_JAR" -F "$BUILD/app-unsigned.apk"
cp "$BUILD/app-unsigned.apk" "$BUILD/app-with-dex.apk"
# aapt add takes the dex path relative to the cwd, so cd into $BUILD first.
(cd "$BUILD" && aapt add app-with-dex.apk classes.dex)

echo "Signing..."
apksigner sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --out "$OUT_DIR/adbwifi-helper.apk" "$BUILD/app-with-dex.apk"

echo "Built: $OUT_DIR/adbwifi-helper.apk"
echo
echo "Install and grant permission (one-time, needs the shell UID):"
echo "  maintain/install-helper.sh"

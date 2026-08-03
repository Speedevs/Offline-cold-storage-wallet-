#!/usr/bin/env bash
#
# Build a signed SeedForge.apk WITHOUT Gradle or Android Studio — just the
# Android SDK build-tools + a JDK. Adjust the paths below for your machine.
#
#   Requirements:
#     - JDK (javac, keytool)               -> JAVA_HOME
#     - Android SDK build-tools + platform -> ANDROID_HOME
#         sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
#
set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
BUILD_TOOLS_VER="${BUILD_TOOLS_VER:-34.0.0}"
PLATFORM="${PLATFORM:-android-34}"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

BT="$ANDROID_HOME/build-tools/$BUILD_TOOLS_VER"
ANDROID_JAR="$ANDROID_HOME/platforms/$PLATFORM/android.jar"
export PATH="$JAVA_HOME/bin:$BT:$PATH"

cd "$(dirname "$0")"
rm -rf build
mkdir -p build/compiled build/classes build/dex build/gen

echo "[1/6] compile resources (aapt2)"
aapt2 compile --dir res -o build/compiled/res.zip

echo "[2/6] link resources + manifest (aapt2)"
aapt2 link -o build/base.ap_ \
  -I "$ANDROID_JAR" \
  --manifest AndroidManifest.xml \
  -A assets \
  --java build/gen \
  --min-sdk-version 21 --target-sdk-version 34 \
  build/compiled/res.zip

echo "[3/6] compile Java (javac, --release 8 for clean dexing)"
javac --release 8 -nowarn -Xlint:none \
  -classpath "$ANDROID_JAR" \
  -d build/classes \
  build/gen/com/speedevs/seedforge/R.java \
  src/com/speedevs/seedforge/*.java

echo "[4/6] dex (d8)"
CLASSES=$(find build/classes -name '*.class')
d8 --release --min-api 21 --lib "$ANDROID_JAR" --output build/dex $CLASSES

echo "[5/6] assemble + align"
cp build/base.ap_ build/app-unsigned.apk
( cd build/dex && zip -q ../app-unsigned.apk classes.dex )
zipalign -f -p 4 build/app-unsigned.apk build/app-aligned.apk

echo "[6/6] sign (apksigner)"
if [ ! -f build/seedforge.keystore ]; then
  keytool -genkeypair -v \
    -keystore build/seedforge.keystore \
    -storepass seedforge -keypass seedforge -alias seedforge \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=SeedForge, OU=speedevs, O=speedevs, C=US" >/dev/null 2>&1
fi
apksigner sign \
  --ks build/seedforge.keystore \
  --ks-pass pass:seedforge --key-pass pass:seedforge \
  --out build/SeedForge.apk \
  build/app-aligned.apk

echo
apksigner verify --print-certs build/SeedForge.apk >/dev/null && echo "signature: OK"
echo "APK ready: $(pwd)/build/SeedForge.apk"

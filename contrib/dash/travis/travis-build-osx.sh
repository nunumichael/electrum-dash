#!/bin/bash
set -ev

export PY37BINDIR=/Library/Frameworks/Python.framework/Versions/3.7/bin/
export PATH=$PATH:$PY37BINDIR
source ./contrib/dash/travis/electrum_dash_version_env.sh;
echo osx build version is $XAZAB_ELECTRUM_VERSION


cd build
if [[ -n $TRAVIS_TAG ]]; then
    BUILD_REPO_URL=https://github.com/dashevo/electrum-dash.git
    git clone --branch $TRAVIS_TAG $BUILD_REPO_URL electrum-dash
    PIP_CMD="sudo python3 -m pip"
else
    git clone .. electrum-dash
    python3 -m virtualenv env
    source env/bin/activate
    PIP_CMD="pip"
fi
cd electrum-dash


if [[ -n $TRAVIS_TAG ]]; then
    git submodule init
    git submodule update

    echo "Building CalinsQRReader..."
    d=contrib/CalinsQRReader
    pushd $d
    rm -fr build
    xcodebuild || fail "Could not build CalinsQRReader"
    popd
fi


$PIP_CMD install --no-dependencies -I \
    -r contrib/deterministic-build/requirements.txt
$PIP_CMD install --no-dependencies -I \
    -r contrib/deterministic-build/requirements-hw.txt
$PIP_CMD install --no-dependencies -I \
    -r contrib/deterministic-build/requirements-binaries-mac.txt
$PIP_CMD install --no-dependencies -I x11_hash>=1.4

$PIP_CMD install --no-dependencies -I \
    -r contrib/deterministic-build/requirements-build-mac.txt

pushd electrum_dash
git clone https://github.com/zebra-lucky/electrum-dash-locale/ locale-repo
mv locale-repo/locale .
rm -rf locale-repo
find locale -name '*.po' -delete
find locale -name '*.pot' -delete
popd

cp contrib/osx/osx.spec .
cp contrib/dash/pyi_runtimehook.py .
cp contrib/dash/pyi_tctl_runtimehook.py .

pyinstaller --clean \
    -y \
    --name electrum-dash-$XAZAB_ELECTRUM_VERSION.bin \
    osx.spec

sudo hdiutil create -fs HFS+ -volname "Xazab Electrum" \
    -srcfolder dist/Xazab\ Electrum.app \
    dist/Xazab-Electrum-$XAZAB_ELECTRUM_VERSION-macosx.dmg

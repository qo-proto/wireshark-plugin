FROM golang:1.25-bookworm

# Install common build tools
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    wget \
    unzip \
    mingw-w64 \
    libreadline-dev \
    clang \
    llvm \
    cmake \
    libxml2-dev \
    libssl-dev \
    zlib1g-dev \
    git \
    patch \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# OSXCross setup for macOS (do this early)
# -----------------------------
RUN git clone https://github.com/tpoechtrager/osxcross /osxcross && \
    cd /osxcross && \
    wget -nc https://github.com/joseluisq/macosx-sdks/releases/download/14.5/MacOSX14.5.sdk.tar.xz && \
    mv MacOSX14.5.sdk.tar.xz tarballs/ && \
    UNATTENDED=yes OSX_VERSION_MIN=10.15 ./build.sh

ENV PATH="/osxcross/target/bin:$PATH"

WORKDIR /build
COPY qotp_export.go qotp_decrypt.c qotp_dissector.lua go.mod go.sum ./
COPY mapping/ ./mapping/

# -----------------------------
# Download Lua 5.4.6 once
# -----------------------------
RUN mkdir -p /lua-src && cd /lua-src && \
    wget https://www.lua.org/ftp/lua-5.4.6.tar.gz && \
    tar xzf lua-5.4.6.tar.gz

# -----------------------------
# Build Lua for Linux (static)
# -----------------------------
RUN cd /lua-src/lua-5.4.6 && \
    make linux CC=gcc CFLAGS="-O2 -fPIC" && \
    mkdir -p /lua/linux && \
    cp src/*.h src/liblua.a /lua/linux/

# -----------------------------
# Linux build (.so) with static Lua
# -----------------------------
RUN go build -buildmode=c-shared -o libqotp_crypto.so qotp_export.go && \
    g++ -shared -fPIC -o qotp_decrypt.so qotp_decrypt.c \
    -I/lua/linux \
    /lua/linux/liblua.a \
    -ldl

# -----------------------------
# Build Lua for Windows (MinGW static)
# -----------------------------
RUN cd /lua-src/lua-5.4.6/src && \
    make clean && \
    make mingw CC=x86_64-w64-mingw32-gcc && \
    mkdir -p /lua/windows && \
    cp lua54.dll liblua.a *.h /lua/windows/

# -----------------------------
# Windows cross-build (.dll) with static Lua
# -----------------------------
RUN go build -buildmode=c-shared -o qotp_crypto.dll qotp_export.go && \
    x86_64-w64-mingw32-g++ -shared -o qotp_decrypt.dll qotp_decrypt.c \
    -I/lua/windows \
    /lua/windows/liblua.a \
    -static-libgcc \
    -static-libstdc++

# Copy Lua 5.4.6 headers for macOS (don't build library - use Wireshark's embedded Lua)
RUN mkdir -p /lua/macos && \
    cp /lua-src/lua-5.4.6/src/*.h /lua/macos/

# macOS build (.so for Lua, .dylib for Go shared lib)
RUN CC=o64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
    go build -buildmode=c-shared -o libqotp_crypto.dylib qotp_export.go && \
    o64-clang++ -shared -o qotp_decrypt_macos.so qotp_decrypt.c \
    -I/lua/macos \
    -undefined dynamic_lookup


VOLUME ["/output"]
# Output files organized by platform:
# Linux: libqotp_crypto.so, qotp_decrypt.so
# Windows: qotp_crypto.dll, qotp_decrypt.dll
# macOS: libqotp_crypto.dylib, qotp_decrypt_macos.so (rename to qotp_decrypt.so when installing)
CMD ["sh", "-c", "cp libqotp_crypto.so qotp_decrypt.so qotp_crypto.dll qotp_decrypt.dll libqotp_crypto.dylib qotp_decrypt_macos.so qotp_dissector.lua /output/"]
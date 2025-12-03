FROM golang:1.25-bookworm

# Install common build tools
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    wget \
    unzip \
    mingw-w64 \
    libreadline-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy project files
COPY qotp_export.go qotp_decrypt.c qotp_dissector.lua go.mod go.sum ./
COPY mapping/ ./mapping/

# Generate mappings
WORKDIR /build/mapping
RUN go mod tidy
RUN go run ./generate_mappings.go ../qotp_dissector.lua

WORKDIR /build

# -----------------------------
# Download Lua 5.3.6 once
# -----------------------------
RUN mkdir -p /lua-src && cd /lua-src && \
    wget https://www.lua.org/ftp/lua-5.3.6.tar.gz && \
    tar xzf lua-5.3.6.tar.gz

# -----------------------------
# Build Lua for Linux (static)
# -----------------------------
RUN cd /lua-src/lua-5.3.6 && \
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
RUN cd /lua-src/lua-5.3.6/src && \
    make clean && \
    make mingw CC=x86_64-w64-mingw32-gcc && \
    mkdir -p /lua/windows && \
    cp lua53.dll liblua.a *.h /lua/windows/

# -----------------------------
# Windows cross-build (.dll) with static Lua
# -----------------------------
RUN go build -buildmode=c-shared -o qotp_crypto.dll qotp_export.go && \
    x86_64-w64-mingw32-g++ -shared -o qotp_decrypt.dll qotp_decrypt.c \
        -I/lua/windows \
        /lua/windows/liblua.a \
        -static-libgcc \
        -static-libstdc++
        
 # -----------------------------
 # OSXCross setup for macOS
 # -----------------------------
 RUN git clone https://github.com/tpoechtrager/osxcross /osxcross && \
     cd /osxcross && \
     wget -nc https://github.com/joseluisq/macosx-sdks/releases/download/14.5/MacOSX14.5.sdk.tar.xz && \
     mv MacOSX14.5.sdk.tar.xz tarballs/ && \
     UNATTENDED=yes OSX_VERSION_MIN=10.15 ./build.sh
 
 ENV PATH="/osxcross/target/bin:$PATH"
 ENV CC=o64-clang
 ENV CXX=o64-clang++
        
# Build Lua for macOS (static)
RUN cd /lua-src/lua-5.3.6/src && \
    make clean && \
    make macosx CC=o64-clang CFLAGS="-O2 -fPIC" && \
    mkdir -p /lua/macos && \
    cp *.h liblua.a /lua/macos/

# macOS build (.dylib) with static Lua
RUN CC=o64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
    go build -buildmode=c-shared -o libqotp_crypto.dylib qotp_export.go && \
    o64-clang++ -shared -o qotp_decrypt.dylib qotp_decrypt.c \
        -I/lua/macos \
        /lua/macos/liblua.a \
        -undefined dynamic_lookup

# Output volume
VOLUME ["/output"]

# Copy all artifacts to output folder
CMD ["sh", "-c", "cp libqotp_crypto.so qotp_decrypt.so qotp_crypto.dll qotp_decrypt.dll qotp_dissector.lua /output/"]

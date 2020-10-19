function addPath {
  case ":$PATH:" in
    *":$1:"*) :;; # already there
    *) PATH="$1:$PATH";; # or PATH="$PATH:$1"
  esac
}

if [[ $(uname -s) == Darwin ]]
then
    addPath /Users/goka/android/ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin
else
    addPath /Users/goka/android/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
fi

export CC=clang
export CXX=clang++
export TARGET_ARCH="-target armv7a-linux-androideabi16"


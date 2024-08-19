//go:build js && wasm
// +build js,wasm

package main
import (
"crypto/md5"
"crypto/sha1"
"crypto/sha256"
"crypto/sha512"
"encoding/hex"
"hash/adler32"
"hash/crc32"
"hash/crc64"
"hash/fnv"
"github.com/attilabuti/go-snefru"
"github.com/cxmcc/tiger"
b512 "github.com/dchest/blake512"
"github.com/ddulesov/gogost/gost34112012256"
"github.com/ddulesov/gogost/gost34112012512"
"github.com/htruong/go-md2"
"github.com/jzelinskie/whirlpool"
"github.com/maoxs2/go-ripemd"
blake "github.com/pedroalbanese/blake256"
"golang.org/x/crypto/md4"
"golang.org/x/crypto/sha3"
)
func processInput(input []byte, s string) string {
if s == "md2" {
h := md2.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "md4" {
h := md4.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "md5" {
h := md5.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha1" {
h := sha1.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_224" || s == "sha224" || s == "sha2-224" {
h := sha256.New224()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_256" || s == "sha256" || s == "sha2-256" {
h := sha256.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_384" || s == "sha384" || s == "sha2-384" {
h := sha512.New384()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_512" || s == "sha512" || s == "sha2-512" {
h := sha512.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_512_224" || s == "sha512_224" || s == "sha2-512-224" {
h := sha512.New512_224()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha2_512_256" || s == "sha512_256" || s == "sha2-512-256" {
h := sha512.New512_256()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_224" {
h := sha3.New224()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_256" {
h := sha3.New256()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_384" {
h := sha3.New384()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_512" {
h := sha3.New512()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_shake128" {
h := sha3.NewShake128()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "sha3_shake256" {
h := sha3.NewShake256()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "adler32" {
h := adler32.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "crc32" {
h := crc32.NewIEEE()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "crc64_iso" {
h := crc64.New(crc64.MakeTable(crc64.ISO))
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "crc64_ecma" {
h := crc64.New(crc64.MakeTable(crc64.ECMA))
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "fnv32" {
h := fnv.New32()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "fnv32a" {
h := fnv.New32a()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "fnv64" {
h := fnv.New64()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "fnv64a" {
h := fnv.New64a()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "tiger" {
h := tiger.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "tiger2" {
h := tiger.New2()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "whirlpool" {
h := whirlpool.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "gost34112012256" {
h := gost34112012256.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "gost34112012512" {
h := gost34112012512.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "snefru256" || s == "snefru" {
h := snefru.NewSnefru256(16)
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "snefru128" {
h := snefru.NewSnefru128(16)
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "ripemd128" {
h := ripemd.New128()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "ripemd160" {
h := ripemd.New160()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "ripemd256" {
h := ripemd.New256()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "ripemd320" {
h := ripemd.New320()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "blake224" {
h := blake.New224()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "blake256" {
h := blake.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "blake384" {
h := b512.New384()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
} else if s == "blake512" {
h := b512.New()
h.Write([]byte(input))
return hex.EncodeToString(h.Sum(nil))
}
return ""
}
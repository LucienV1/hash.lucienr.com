package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"flags"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"net/http"
	"os"
	"strings"

	"github.com/attilabuti/go-snefru"
	tigerpkg "github.com/cxmcc/tiger"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost34112012512"
	"github.com/ddulesov/gogost/gost341194"
	"github.com/htruong/go-md2"
	"github.com/jzelinskie/whirlpool"
	"github.com/maoxs2/go-ripemd"
	blake "github.com/pedroalbanese/blake256"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var response string
	if r.Method != "GET" && r.URL.Path == "/" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	} else if r.URL.Path == "/" && r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head></head><body><p>PLACEHOLDER</p></body></html>`))
		return
	} else if strings.HasPrefix(r.URL.Path, "/md2") {
		if r.Method == "GET" {
			if r.URL.path == "/md2" {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				md2.Sum(r.URL.Query().Get("data"))
			}
		} else if r.Method == "POST" {

	}
		
}

func main() {
	address := flags.String("a", "127.0.0.1:3339", "Address to listen on, default is 127.0.0.1:3339")
	flags.Parse()

	md2 := md2.New()
	md4 := md4.New()
	md5 := md5.New()
	sha1 := sha1.New()
	sha2_224 := sha256.New224()
	sha2_256 := sha256.New()
	sha2_384 := sha512.New384()
	sha2_512 := sha512.New()
	sha2_512_224 := sha512.New512_224()
	sha2_512_256 := sha512.New512_256()
	sha3_224 := sha3.New224()
	sha3_256 := sha3.New256()
	sha3_384 := sha3.New384()
	sha3_512 := sha3.New512()
	sha3_shake128 := sha3.NewShake128()
	sha3_shake256 := sha3.NewShake256()
	adler32 := adler32.New()
	crc32 := crc32.NewIEEE()
	crc64_iso := crc64.New(crc64.MakeTable(crc64.ISO))
	crc64_ecma := crc64.New(crc64.MakeTable(crc64.ECMA))
	fnv32 := fnv.New32()
	fnv32a := fnv.New32a()
	fnv64 := fnv.New64()
	fnv64a := fnv.New64a()
	tiger := tigerpkg.New()
	tiger2 := tigerpkg.New2()
	whirlpool := whirlpool.New()
	gost34112012256 := gost34112012256.New()
	gost34112012512 := gost34112012512.New()
	gost341194 := gost341194.New()
	snefru256 := snefru.NewSnefru256()
	snefru128 := snefru.NewSnefru128()
	ripemd128 := ripemd.New128()
	ripemd160 := ripemd.New160()
	ripemd256 := ripemd.New256()
	ripemd320 := ripemd.New320()
	blake224 := blake.New224()
	blake256 := blake.New()
	blake384 := blake.New384()
	blake512 := blake.New512()

	http.HandleFunc("/", handler)
	http.ListenAndServe(*address, nil)
}

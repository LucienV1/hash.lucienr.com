package main

import (
	"crypto/md2"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flags"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"net/http"
	"strings"

	"github.com/attilabuti/go-snefru"
	"github.com/cxmcc/tiger"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost34112012512"

	// "github.com/htruong/go-md2"
	"github.com/jzelinskie/whirlpool"
	"github.com/maoxs2/go-ripemd"
	blake "github.com/pedroalbanese/blake256"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.URL.Path == "/" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	} else if r.URL.Path == "/" && r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head></head><body><p>PLACEHOLDER</p></body></html>`))
		return
	} else {
		if strings.HasPrefix(r.URL.Path, "/md2") {
			hashing(w, r, md2.New(), len("/md2/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/md4") {
			hashing(w, r, md4.New(), len("/md4/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/md5") {
			hashing(w, r, md5.New(), len("/md5/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha1") {
			hashing(w, r, sha1.New(), len("/sha1/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha224") || strings.HasPrefix(r.URL.Path, "/sha2_224") || strings.HasPrefix(r.URL.Path, "/sha2-224") {
			hashing(w, r, sha256.New224(), len("/sha224/"))
			return
		} else if r.URL.Path == "/sha256" || r.URL.Path == "/sha2_256" || r.URL.Path == "/sha2-256" {
			hashing(w, r, sha256.New())
			return
		} else if r.URL.Path == "/sha384" || r.URL.Path == "/sha2_384" || r.URL.Path == "/sha2-384" {
			hashing(w, r, sha512.New384())
			return
		} else if r.URL.Path == "/sha512" || r.URL.Path == "/sha2_512" || r.URL.Path == "/sha2-512" {
			hashing(w, r, sha512.New())
			return
		} else if r.URL.Path == "/sha512_224" || r.URL.Path == "/sha2_512_224" || r.URL.Path == "/sha2-512-224" {
			hashing(w, r, sha512.New512_224())
			return
		} else if r.URL.Path == "/sha512_256" || r.URL.Path == "/sha2_512_256" || r.URL.Path == "/sha2-512-256" {
			hashing(w, r, sha512.New512_256())
			return
		} else if r.URL.Path == "/sha3_224" || r.URL.Path == "/sha3-224" {
			hashing(w, r, sha3.New224())
			return
		} else if r.URL.Path == "/sha3_256" || r.URL.Path == "/sha3-256" {
			hashing(w, r, sha3.New256())
			return
		} else if r.URL.Path == "/sha3_384" || r.URL.Path == "/sha3-384" {
			hashing(w, r, sha3.New384())
			return
		} else if r.URL.Path == "/sha3_512" || r.URL.Path == "/sha3-512" {
			hashing(w, r, sha3.New512())
			return
		} else if r.URL.Path == "/sha3_shake128" || r.URL.Path == "/sha3-shake128" {
			hashing(w, r, sha3.NewShake128())
			return
		} else if r.URL.Path == "/sha3_shake256" || r.URL.Path == "/sha3-shake256" {
			hashing(w, r, sha3.NewShake256())
			return
		} else if r.URL.Path == "/adler32" {
			hashing(w, r, adler32.New())
			return
		} else if r.URL.Path == "/crc32" {
			hashing(w, r, crc32.NewIEEE())
			return
		} else if r.URL.Path == "/crc64_iso" {
			hashing(w, r, crc64.New(crc64.MakeTable(crc64.ISO)))
			return
		} else if r.URL.Path == "/crc64_ecma" {
			hashing(w, r, crc64.New(crc64.MakeTable(crc64.ECMA)))
			return
		} else if r.URL.Path == "/fnv32" {
			hashing(w, r, fnv.New32())
			return
		} else if r.URL.Path == "/fnv32a" {
			hashing(w, r, fnv.New32a())
			return
		} else if r.URL.Path == "/fnv64" {
			hashing(w, r, fnv.New64())
			return
		} else if r.URL.Path == "/fnv64a" {
			hashing(w, r, fnv.New64a())
			return
		} else if r.URL.Path == "/tiger" {
			hashing(w, r, tiger.New())
			return
		} else if r.URL.Path == "/tiger2" {
			hashing(w, r, tiger.New2())
			return
		} else if r.URL.Path == "/whirlpool" {
			hashing(w, r, whirlpool.New())
			return
		} else if r.URL.Path == "/gost34112012256" || r.URL.Path == "/gost3411-2012-256" || r.URL.Path == "gost256" {
			hashing(w, r, gost34112012256.New())
			return
		} else if r.URL.Path == "/gost34112012512" || r.URL.Path == "/gost3411-2012-512" || r.URL.Path == "gost512" {
			hashing(w, r, gost34112012512.New())
			return
		} else if r.URL.Path == "/snefru256" || r.URL.Path == "/snefru-256" || r.URL.Path == "/snefru_256" {
			hashing(w, r, snefru.NewSnefru256(16))
			return
		} else if r.URL.Path == "/snefru128" || r.URL.Path == "/snefru-128" || r.URL.Path == "/snefru_128" {
			hashing(w, r, snefru.NewSnefru128(16))
			return
		} else if r.URL.Path == "/ripemd128" || r.URL.Path == "/ripemd-128" || r.URL.Path == "/ripemd_128" {
			hashing(w, r, ripemd.New128())
			return
		} else if r.URL.Path == "/ripemd160" || r.URL.Path == "/ripemd-160" || r.URL.Path == "/ripemd_160" {
			hashing(w, r, ripemd.New160())
			return
		} else if r.URL.Path == "/ripemd256" || r.URL.Path == "/ripemd-256" || r.URL.Path == "/ripemd_256" {
			hashing(w, r, ripemd.New256())
			return
		} else if r.URL.Path == "/ripemd320" || r.URL.Path == "/ripemd-320" || r.URL.Path == "/ripemd_320" {
			hashing(w, r, ripemd.New320())
			return
		} else if r.URL.Path == "/blake224" || r.URL.Path == "/blake-224" || r.URL.Path == "/blake_224" {
			hashing(w, r, blake.New224())
			return
		} else if r.URL.Path == "/blake256" || r.URL.Path == "/blake-256" || r.URL.Path == "/blake_256" {
			hashing(w, r, blake.New())
			return
		} else if r.URL.Path == "/blake384" || r.URL.Path == "/blake-384" || r.URL.Path == "/blake_384" {
			hashing(w, r, blake.New384())
			return
		} else if r.URL.Path == "/blake512" || r.URL.Path == "/blake-512" || r.URL.Path == "/blake_512" {
			hashing(w, r, blake.New512())
			return
		} else {
			http.Error(w, "Not found, or invalid algorithim", http.StatusNotFound)
			return
		}
	}
}

func hashing(w http.ResponseWriter, r *http.Request, h hash.Hash, l int) {
	if r.Method == "GET" {
		if r.URL.Path == "/md2" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			m := md2.New()
			m.Write(r.URL.Query().Get("data"))
			w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
			return
		} else {
			if r.URL.Path == strings.HasSuffix(r.URL.Path, "/") {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				m := md2.New()
				m.Write("")
				w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
				return
			} else if strings.HasPrefix(r.URL.Path, "/md2/") {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				m := md2.New()
				m.Write([]byte(r.URL.Path[l:]))
				w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
				return
			}
		}
	} else if r.Method == "POST" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		m := md2.New()
		m.Write(r.Body)
		w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
		return
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func main() {
	address := flags.String("a", "127.0.0.1:3339", "Address to listen on, default is 127.0.0.1:3339")
	flags.Parse()

	//	md4 := md4.New()
	//	md5 := md5.New()
	//	sha1 := sha1.New()
	//	sha2_224 := sha256.New224()
	//	sha2_256 := sha256.New()
	//	sha2_384 := sha512.New384()
	//	sha2_512 := sha512.New()
	//	sha2_512_224 := sha512.New512_224()
	//	sha2_512_256 := sha512.New512_256()
	//	sha3_224 := sha3.New224()
	//	sha3_256 := sha3.New256()
	//	sha3_384 := sha3.New384()
	//	sha3_512 := sha3.New512()
	//	sha3_shake128 := sha3.NewShake128()
	//	sha3_shake256 := sha3.NewShake256()
	//	adler32 := adler32.New()
	//	crc32 := crc32.NewIEEE()
	//	crc64_iso := crc64.New(crc64.MakeTable(crc64.ISO))
	//	crc64_ecma := crc64.New(crc64.MakeTable(crc64.ECMA))
	//	fnv32 := fnv.New32()
	//	fnv32a := fnv.New32a()
	//	fnv64 := fnv.New64()
	//	fnv64a := fnv.New64a()
	//	tiger := tigerpkg.New()
	//	tiger2 := tigerpkg.New2()
	//	whirlpool := whirlpool.New()
	//	gost34112012256 := gost34112012256.New()
	//	gost34112012512 := gost34112012512.New()
	//	gost341194 := gost341194.New()
	//	snefru256 := snefru.NewSnefru256()
	//	snefru128 := snefru.NewSnefru128()
	//	ripemd128 := ripemd.New128()
	//	ripemd160 := ripemd.New160()
	//	ripemd256 := ripemd.New256()
	//	ripemd320 := ripemd.New320()
	//	blake224 := blake.New224()
	//	blake256 := blake.New()
	//	blake384 := blake.New384()
	//	blake512 := blake.New512()

	http.HandleFunc("/", handler)
	http.ListenAndServe(*address, nil)
}

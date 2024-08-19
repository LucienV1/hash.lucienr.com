package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"net/http"
	"strings"

	"github.com/attilabuti/go-snefru"
	"github.com/cxmcc/tiger"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost34112012512"

	b512 "github.com/dchest/blake512"
	"github.com/htruong/go-md2"
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
		w.Write([]byte(`<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Online hashing">
    <meta name="keywords" content="hashing, online, webassembly">
    <meta name"og:title" content="Online hashing">
    <meta name="og:description" content="Online hashing">
    <meta name="og:type" content="website">
<title>online hashing</title>
<style>
    .famfamfam-mini {
        background: url(https://raw.githubusercontent.com/legacy-icons/famfamfam-mini/master/dist/sprite/famfamfam-mini.png) no-repeat;
        background-size: 192px 192px
    }

    .famfamfam-mini.action_refresh {
        width: 16px;
        height: 16px;
        background-position: -32px -16px
    }

    .hidden {
        display: none
    }

    .point {
        cursor: pointer
    }
</style>
</head>
<body>
<p>Input:</p>
<div>
    <input id="textRadio" name="inputType" type="radio" value="text" checked>
    <label for="textRadio">Text</label>
    <input id="fileRadio" name="inputType" type="radio" value="file">
    <label for="fileRadio">File</label>
</div>
<div id="intext">
    <p><textarea cols="50" id="input" rows="4"></textarea></p>
    <p class="point famfamfam-mini action_refresh" onclick="document.getElementById('input').value = '';"></p>
</div>
<div id="infile" class="hidden">
    <p><input type="file" id="file" name="file"></p>
    <p class="point famfamfam-mini action_refresh" onclick="document.getElementById('file').value = '';"></p>
</div>
<script>
    document.addEventListener('DOMContentLoaded', function () {
        const textRadio = document.getElementById('textRadio');
        const fileRadio = document.getElementById('fileRadio');
        const intext = document.getElementById('intext');
        const infile = document.getElementById('infile');
        const textArea = document.getElementById('input');
        const fileInput = document.getElementById('file');
        const algorithmSelect = document.getElementById('algorithm');

        function toggleVisibility() {
            if (textRadio.checked) {
                intext.classList.remove('hidden');
                infile.classList.add('hidden');
            } else if (fileRadio.checked) {
                intext.classList.add('hidden');
                infile.classList.remove('hidden');
            }
        }

        // Set initial state
        textRadio.checked = true;
        fileRadio.checked = false;
        intext.classList.remove('hidden');
        infile.classList.add('hidden');

        textRadio.addEventListener('change', toggleVisibility);
        fileRadio.addEventListener('change', toggleVisibility);

        async function loadWasm() {
            const response = await fetch('https://cdn.example.com/h.wasm');
            const buffer = await response.arrayBuffer();
            const wasmModule = await WebAssembly.instantiate(buffer);
            return wasmModule.instance.exports;
        }

        // Load the WebAssembly module
        loadWasm().then(wasmExports => {
            textArea.addEventListener('input', function () {
                if (textRadio.checked) {
                    wasmExports.ProcessInput(textArea.value, algorithmSelect.value);
                }
            });

            algorithmSelect.addEventListener('change', function () {
                if (textRadio.checked) {
                    wasmExports.ProcessInput(textArea.value, algorithmSelect.value);
                } else if (fileRadio.checked) {
                    const file = fileInput.files[0];
                    if (file) {
                        const reader = new FileReader();
                        reader.onload = function (event) {
                            const arrayBuffer = event.target.result;
                            const uint8Array = new Uint8Array(arrayBuffer);
                            wasmExports.ProcessInput(uint8Array, algorithmSelect.value);
                        };
                        reader.readAsArrayBuffer(file);
                    }
                }
            });

            fileInput.addEventListener('change', function () {
                const file = fileInput.files[0];
                if (file && fileRadio.checked) {
                    const reader = new FileReader();
                    reader.onload = function (event) {
                        const arrayBuffer = event.target.result;
                        const uint8Array = new Uint8Array(arrayBuffer);
                        wasmExports.ProcessInput(uint8Array, algorithmSelect.value);
                    };
                    reader.readAsArrayBuffer(file);
                }
            });
        }).catch(console.error);
    });
</script>
<p>Output:</p><textarea cols=50 id=output rows=4></textarea></p>
<p><select id=algorithm>
        <option value=md2>MD2</option>
        <option value=md4>MD4</option>
        <option value=md5>MD5</option>
        <option value=sha1>SHA-1</option>
        <option value=sha2_224>SHA-2 224</option>
        <option value=sha2_256>SHA-2 256</option>
        <option value=sha2_384>SHA-2 384</option>
        <option value=sha2_512>SHA-2 512</option>
        <option value=sha2_512_224>SHA-2 512/224</option>
        <option value=sha2_512_256>SHA-2 512/256</option>
        <option value=sha3_224>SHA-3 224</option>
        <option value=sha3_256>SHA-3 256</option>
        <option value=sha3_384>SHA-3 384</option>
        <option value=sha3_512>SHA-3 512</option>
        <option value=sha3_shake128>SHA-3 Shake128</option>
        <option value=sha3_shake256>SHA-3 Shake256</option>
        <option value=adler32>Adler-32</option>
        <option value=crc32>CRC-32</option>
        <option value=crc64_iso>CRC-64 ISO</option>
        <option value=crc64_ecma>CRC-64 ECMA</option>
        <option value=fnv32>FNV-32</option>
        <option value=fnv32a>FNV-32a</option>
        <option value=fnv64>FNV-64</option>
        <option value=fnv64a>FNV-64a</option>
        <option value=tiger>Tiger</option>
        <option value=tiger2>Tiger2</option>
        <option value=whirlpool>Whirlpool</option>
        <option value=gost34112012256>GOST 3411-2012 256</option>
        <option value=gost34112012512>GOST 3411-2012 512</option>
        <option value=snefru256>Snefru-256</option>
        <option value=snefru128>Snefru-128</option>
        <option value=ripemd128>RIPEMD-128</option>
        <option value=ripemd160>RIPEMD-160</option>
        <option value=ripemd256>RIPEMD-256</option>
        <option value=ripemd320>RIPEMD-320</option>
        <option value=blake224>BLAKE-224</option>
        <option value=blake256>BLAKE-256</option>
        <option value=blake384>BLAKE-384</option>
        <option value=blake512>BLAKE-512</option>
    </select></p>
</body>

</html>`))
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
		} else if strings.HasPrefix(r.URL.Path, "/sha256") || strings.HasPrefix(r.URL.Path, "/sha2_256") || strings.HasPrefix(r.URL.Path, "/sha2-256") {
			hashing(w, r, sha256.New(), len("/sha256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha384") || strings.HasPrefix(r.URL.Path, "/sha2_384") || strings.HasPrefix(r.URL.Path, "/sha2-384") {
			hashing(w, r, sha512.New384(), len("/sha384/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha512") || strings.HasPrefix(r.URL.Path, "/sha2_512") || strings.HasPrefix(r.URL.Path, "/sha2-512") {
			hashing(w, r, sha512.New(), len("/sha512/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha512_224") || strings.HasPrefix(r.URL.Path, "/sha2_512_224") || strings.HasPrefix(r.URL.Path, "/sha2-512-224") {
			hashing(w, r, sha512.New512_224(), len("/sha512_224/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha512_256") || strings.HasPrefix(r.URL.Path, "/sha2_512_256") || strings.HasPrefix(r.URL.Path, "/sha2-512-256") {
			hashing(w, r, sha512.New512_256(), len("/sha512_256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_224") || strings.HasPrefix(r.URL.Path, "/sha3-224") {
			hashing(w, r, sha3.New224(), len("/sha3_224/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_256") || strings.HasPrefix(r.URL.Path, "/sha3-256") {
			hashing(w, r, sha3.New256(), len("/sha3_256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_384") || strings.HasPrefix(r.URL.Path, "/sha3-384") {
			hashing(w, r, sha3.New384(), len("/sha3_384/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_512") || strings.HasPrefix(r.URL.Path, "/sha3-512") {
			hashing(w, r, sha3.New512(), len("/sha3_512/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_shake128") || strings.HasPrefix(r.URL.Path, "/sha3-shake128") {
			hashing(w, r, sha3.NewShake128(), len("/sha3_shake128/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/sha3_shake256") || strings.HasPrefix(r.URL.Path, "/sha3-shake256") {
			hashing(w, r, sha3.NewShake256(), len("/sha3_shake256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/adler32") {
			hashing(w, r, adler32.New(), len("/adler32/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/crc32") {
			hashing(w, r, crc32.NewIEEE(), len("/crc32/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/crc64_iso") {
			hashing(w, r, crc64.New(crc64.MakeTable(crc64.ISO)), len("/crc64_iso/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/crc64_ecma") {
			hashing(w, r, crc64.New(crc64.MakeTable(crc64.ECMA)), len("/crc64_ecma/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/fnv32") {
			hashing(w, r, fnv.New32(), len("/fnv32/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/fnv32a") {
			hashing(w, r, fnv.New32a(), len("/fnv32a/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/fnv64") {
			hashing(w, r, fnv.New64(), len("/fnv64/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/fnv64a") {
			hashing(w, r, fnv.New64a(), len("/fnv64a/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/tiger") {
			hashing(w, r, tiger.New(), len("/tiger/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/tiger2") {
			hashing(w, r, tiger.New2(), len("/tiger2/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/whirlpool") {
			hashing(w, r, whirlpool.New(), len("/whirlpool/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/gost34112012256") || strings.HasPrefix(r.URL.Path, "/gost3411-2012-256") || strings.HasPrefix(r.URL.Path, "/gost256") {
			hashing(w, r, gost34112012256.New(), len("/gost34112012256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/gost34112012512") || strings.HasPrefix(r.URL.Path, "/gost3411-2012-512") || strings.HasPrefix(r.URL.Path, "/gost512") {
			hashing(w, r, gost34112012512.New(), len("/gost34112012512/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/snefru256") || strings.HasPrefix(r.URL.Path, "/snefru-256") || strings.HasPrefix(r.URL.Path, "/snefru_256") {
			hashing(w, r, snefru.NewSnefru256(16), len("/snefru256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/snefru128") || strings.HasPrefix(r.URL.Path, "/snefru-128") || strings.HasPrefix(r.URL.Path, "/snefru_128") {
			hashing(w, r, snefru.NewSnefru128(16), len("/snefru128/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/ripemd128") || strings.HasPrefix(r.URL.Path, "/ripemd-128") || strings.HasPrefix(r.URL.Path, "/ripemd_128") {
			hashing(w, r, ripemd.New128(), len("/ripemd128/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/ripemd160") || strings.HasPrefix(r.URL.Path, "/ripemd-160") || strings.HasPrefix(r.URL.Path, "/ripemd_160") {
			hashing(w, r, ripemd.New160(), len("/ripemd160/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/ripemd256") || strings.HasPrefix(r.URL.Path, "/ripemd-256") || strings.HasPrefix(r.URL.Path, "/ripemd_256") {
			hashing(w, r, ripemd.New256(), len("/ripemd256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/ripemd320") || strings.HasPrefix(r.URL.Path, "/ripemd-320") || strings.HasPrefix(r.URL.Path, "/ripemd_320") {
			hashing(w, r, ripemd.New320(), len("/ripemd320/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/blake224") || strings.HasPrefix(r.URL.Path, "/blake-224") || strings.HasPrefix(r.URL.Path, "/blake_224") {
			hashing(w, r, blake.New224(), len("/blake224/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/blake256") || strings.HasPrefix(r.URL.Path, "/blake-256") || strings.HasPrefix(r.URL.Path, "/blake_256") {
			hashing(w, r, blake.New(), len("/blake256/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/blake384") || strings.HasPrefix(r.URL.Path, "/blake-384") || strings.HasPrefix(r.URL.Path, "/blake_384") {
			hashing(w, r, b512.New384(), len("/blake384/"))
			return
		} else if strings.HasPrefix(r.URL.Path, "/blake512") || strings.HasPrefix(r.URL.Path, "/blake-512") || strings.HasPrefix(r.URL.Path, "/blake_512") {
			hashing(w, r, b512.New(), len("/blake512/"))
			return
		} else {
			http.Error(w, "Not found, or invalid algorithim", http.StatusNotFound)
			return
		}
	}
}

func hashing(w http.ResponseWriter, r *http.Request, m hash.Hash, l int) {
	if r.Method == "GET" {
		if !strings.HasSuffix(r.URL.Path[l-1:], "/") {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			m.Write([]byte(r.URL.Query().Get("data")))
			w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
			return
		} else {
			if strings.HasSuffix(r.URL.Path[l-1:], "/") {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				m.Write([]byte(""))
				w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
				return
			} else if string(r.URL.Path[l-1]) == "/" && string(r.URL.Path[l:]) != "" {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				m.Write([]byte(r.URL.Path[l:]))
				w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
				return
			}
		}
	} else if r.Method == "POST" && r.URL.Path[l-1:] == "/" || r.URL.Path[l-1:] == "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		content, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}
		m.Write(content)
		w.Write([]byte(hex.EncodeToString(m.Sum(nil))))
		return
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func main() {
	address := flag.String("a", "127.0.0.1:3339", "Address to listen on, default is 127.0.0.1:3339")
	flag.Parse()
	http.HandleFunc("/", handler)
	http.ListenAndServe(*address, nil)
}

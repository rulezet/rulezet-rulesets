import "hash"
rule GH_PM64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "fe6c0097412b2c7b7f4b8a489004dd14"
}
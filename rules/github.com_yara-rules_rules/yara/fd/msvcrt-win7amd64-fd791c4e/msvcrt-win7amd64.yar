import "hash"
rule msvcrt_Win7AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "c8fc794cc5a22b5a1e0803b0b8acce77"
}
import "hash"
rule msvcrt_WIN8x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "95490c2b284a9bb63f0ee49254ab727e"
}
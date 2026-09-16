import "hash"
rule msvcrt_WIN8AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "33c59fcdf027470e0ab1d366f54a6ebf"
}
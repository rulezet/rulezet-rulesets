import "hash"
rule Vbr {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "961d2fd68fde2ae0b7c52e0c90767d0d"
}
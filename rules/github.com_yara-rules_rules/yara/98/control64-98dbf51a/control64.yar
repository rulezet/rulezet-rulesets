import "hash"
rule Control64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "bec30379078d5c5c7845d3be33707b89"
}
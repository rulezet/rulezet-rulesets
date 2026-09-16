import "hash"
rule MemStub32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "8987652f26732607b769247adb4e9cce"
}
import "hash"
rule MemStub64_GH1 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "2350403a09e6928f0a7ba5d74da58cb9"
}
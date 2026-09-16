import "hash"
rule MemStub32_GH1 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "0a579ad25fdd4db8110aac4dbb7d2da3"
}
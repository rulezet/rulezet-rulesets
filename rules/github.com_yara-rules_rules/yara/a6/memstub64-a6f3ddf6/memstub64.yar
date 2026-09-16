import "hash"
rule MemStub64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "6b5b46d3212fc3fc5b455d9efd8d3ffa"
}
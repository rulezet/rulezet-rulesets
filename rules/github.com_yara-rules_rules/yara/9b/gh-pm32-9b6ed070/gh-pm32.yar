import "hash"
rule GH_PM32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "2f2c5b3f3b1f97908074f526ac90a28d"
}
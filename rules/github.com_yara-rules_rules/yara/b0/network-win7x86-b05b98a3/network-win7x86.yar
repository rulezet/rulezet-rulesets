import "hash"
rule Network_Win7x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "548889baed7768b828d9c2f373abd225"
}
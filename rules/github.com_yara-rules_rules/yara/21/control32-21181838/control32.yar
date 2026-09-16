import "hash"
rule Control32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "b3dc808fc7cb4492669ec019911ef22a"
}
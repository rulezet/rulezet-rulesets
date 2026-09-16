import "hash"
rule msvcrt_Win7x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "7713e5c5a48b020c9575b1b50f2e5e9e"
}
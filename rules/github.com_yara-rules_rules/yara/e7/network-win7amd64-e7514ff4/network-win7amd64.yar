import "hash"
rule Network_Win7AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "eb92031a38f17d0e63285b5142b31966"
}
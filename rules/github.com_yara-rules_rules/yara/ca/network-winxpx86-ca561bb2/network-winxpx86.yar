import "hash"
rule Network_WinXPx86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "877341a16d5d223435c43a9db7f721bc"
}
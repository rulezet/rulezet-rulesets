import "hash"
rule RabbitStew64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "fa415b6280104e813770df520b303897"
}
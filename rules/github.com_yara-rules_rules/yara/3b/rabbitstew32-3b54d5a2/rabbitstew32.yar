import "hash"
rule RabbitStew32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "a9d2e8ae5ddbf8f2842d96f7de2faef8"
}
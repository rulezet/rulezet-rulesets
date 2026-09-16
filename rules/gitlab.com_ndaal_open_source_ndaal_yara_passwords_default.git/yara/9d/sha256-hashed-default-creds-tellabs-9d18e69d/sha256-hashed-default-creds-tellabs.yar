rule sha256_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa0fdd6f1c979d680cd19cd9a6c7b78cd1422ff0864f2de7e33d2798676723db"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="f0d9e2e1e43a963b440989efa139e558d12600d61a12de05ffc6d24ad04f5024"
    $a3="dc4921803d0d37b86b27dd795b0bf3a7c9ac718d64a1ff002780c9963fb32c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
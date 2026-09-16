rule nthash_hashed_default_creds_google
{
    meta:
        id = "2JTcNUOpUhj8d9h6BqWFsH"
        fingerprint = "1bb4d34f5c9e8c3e6a48cb956ed4a27431dc2464d2d8bd9a10b29d62b7cdd025"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for google."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf5ee119f348ff0b84ec89269eb171ad"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
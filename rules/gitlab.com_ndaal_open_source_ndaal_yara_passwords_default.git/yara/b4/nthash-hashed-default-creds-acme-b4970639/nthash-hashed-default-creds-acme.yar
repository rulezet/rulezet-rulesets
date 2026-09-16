rule nthash_hashed_default_creds_acme
{
    meta:
        id = "tI0UosA0eGXmVMP7JZihz"
        fingerprint = "14979f555a9c4e4ad0cb2d14a491eb8feab06210ddd81aba66fbd05d8afb1f18"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acme."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e33132163272e7727008bccd2afd2531"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
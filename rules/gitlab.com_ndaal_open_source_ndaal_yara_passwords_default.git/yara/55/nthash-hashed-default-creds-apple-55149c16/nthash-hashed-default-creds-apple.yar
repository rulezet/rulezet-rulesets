rule nthash_hashed_default_creds_apple
{
    meta:
        id = "5tEdMmoHI2uu19yQzZorgm"
        fingerprint = "402f3e382ae13b2708fde3c91f2aaa9fb96c036e257cab11d1bfef836cd29876"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apple."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a06f7868e4f85e60a204c14be4be3e7"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="2a4fe9fc69b28fcf4e0461cf6694c46c"
    $a5="d41b88d250b95c6c7b52a9e89ea7a9d1"
    $a6="db51013b2730e1f16df6db7c3a73ad60"
    $a7="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
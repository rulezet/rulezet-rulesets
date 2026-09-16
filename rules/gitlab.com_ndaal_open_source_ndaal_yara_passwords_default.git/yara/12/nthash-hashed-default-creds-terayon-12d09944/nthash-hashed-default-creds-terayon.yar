rule nthash_hashed_default_creds_terayon
{
    meta:
        id = "7ZK3Mj2ZHRTkjKWrxKOXVW"
        fingerprint = "2d4ef277bcd1b37a8a8bcb4d1e868db57ce5a65b5acd1f11fd6f5137f8cb0a0c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for terayon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="57d583aa46d571502aad4bb7aea09c70"
    $a2="7f059bf7155685cf614f0406424f915e"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
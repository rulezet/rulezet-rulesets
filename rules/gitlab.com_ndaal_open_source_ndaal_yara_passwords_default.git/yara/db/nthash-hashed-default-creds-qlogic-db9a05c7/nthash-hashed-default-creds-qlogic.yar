rule nthash_hashed_default_creds_qlogic
{
    meta:
        id = "vS5GsMjrSuG5OWrD9QQ7L"
        fingerprint = "77592dc377eef18be827c9b5430395893998fd60e8c065d34921e13296ef7030"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for qlogic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="2fda249af11f4fb8e7150b41f5b58c50"
    $a3="2fda249af11f4fb8e7150b41f5b58c50"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
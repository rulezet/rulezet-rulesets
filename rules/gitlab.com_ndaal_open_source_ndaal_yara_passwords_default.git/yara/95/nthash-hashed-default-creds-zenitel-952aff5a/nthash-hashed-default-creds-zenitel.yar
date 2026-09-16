rule nthash_hashed_default_creds_zenitel
{
    meta:
        id = "6sbYhcvQ5LLuXSQa5R0vSW"
        fingerprint = "bd61ecc3733d8ab3f8a1691155d6b8ea9ef4032c8ce3b4ef967ea807271b397d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f28ed59b5ce5a4fcdedb252a5d0a03e"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8e747bfa7b0dd3bc3dadd19e2c673b6e"
    $a3="11a01c4a0f2f228796c93fa0ca1a634d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
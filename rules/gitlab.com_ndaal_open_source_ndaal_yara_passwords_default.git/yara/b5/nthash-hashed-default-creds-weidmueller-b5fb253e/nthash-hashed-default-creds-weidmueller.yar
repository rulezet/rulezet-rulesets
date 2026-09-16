rule nthash_hashed_default_creds_weidmueller
{
    meta:
        id = "6uDQeJkINF9KlkvEDSbj19"
        fingerprint = "a85c900da19bed8e6e8b9cd5dc458a04e505ee5adc342d30bec4fd549fa5e3af"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weidmueller."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d59b01ca457786989e6f038f4caa7ec"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
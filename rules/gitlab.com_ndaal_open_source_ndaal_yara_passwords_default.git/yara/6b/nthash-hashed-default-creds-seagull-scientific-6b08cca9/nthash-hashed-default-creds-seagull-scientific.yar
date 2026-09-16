rule nthash_hashed_default_creds_seagull_scientific
{
    meta:
        id = "5mtsf2EJrrmfZcs0InDmRP"
        fingerprint = "3b632e42a9d68dcb64cdc7fe87746c327a25d1acd4da128a49381fa62034f03c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
    $a2="467799ec546cddb461f187080eebb40b"
    $a3="467799ec546cddb461f187080eebb40b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
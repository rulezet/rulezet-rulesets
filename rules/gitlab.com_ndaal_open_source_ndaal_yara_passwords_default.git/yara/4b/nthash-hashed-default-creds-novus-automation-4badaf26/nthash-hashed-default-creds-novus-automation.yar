rule nthash_hashed_default_creds_novus_automation
{
    meta:
        id = "63Ft5xa4k4YzjDod8uCEWk"
        fingerprint = "05e67b6889417c6f573c3a2bf66bd4f98c39b2ee132a0dd72286daa2ef04670c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for novus_automation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f759843b12f1e0db7e3646ac22c5cb7"
    $a1="5f759843b12f1e0db7e3646ac22c5cb7"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
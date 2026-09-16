rule nthash_hashed_default_creds_hp_server_automation_web
{
    meta:
        id = "7FjKRKrTaQxFCrNVTRPt3F"
        fingerprint = "ed96cf4efd2c8d91261c9b6d20c6427fbe0b9069019cdfbf7c3ab6aa1d8a3f76"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp_server_automation_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="e5921f0c30790b7a070e1968593b39d8"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
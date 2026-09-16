rule nthash_hashed_default_creds_mandarin_library_automation
{
    meta:
        id = "7LWh6DQE7F46SzrwgDw1FJ"
        fingerprint = "4110b4079bb9e55dd8ee801083ae985473a6a727d0b9838f509ddb710933e2a4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mandarin_library_automation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="533131a81ed39ed70c136c38e44a9161"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
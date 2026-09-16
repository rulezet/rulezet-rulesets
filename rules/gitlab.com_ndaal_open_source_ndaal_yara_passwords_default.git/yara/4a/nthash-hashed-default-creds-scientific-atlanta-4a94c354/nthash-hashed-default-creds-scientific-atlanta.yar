rule nthash_hashed_default_creds_scientific_atlanta
{
    meta:
        id = "3OGbNMp0IOFWOgnDLQoigH"
        fingerprint = "7c45d67b34d4f14f539f76c18832044e3ca4bcda12bc1f2ee5a05aa6fb9c05df"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scientific_atlanta."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7aea30a26d330932243ec9f419c7ea51"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
rule nthash_hashed_default_creds_virtual_programming
{
    meta:
        id = "3VaVTFELlfFw92H48zR9a0"
        fingerprint = "66f2c4933637baa7f61a113d91feea08d03ee8d446bf0a4d1dd0d8f0df8eea8a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for virtual_programming."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="501727dba002af115d12260f8821feff"
    $a3="501727dba002af115d12260f8821feff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
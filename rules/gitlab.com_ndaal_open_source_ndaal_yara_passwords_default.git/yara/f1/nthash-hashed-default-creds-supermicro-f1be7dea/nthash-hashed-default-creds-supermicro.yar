rule nthash_hashed_default_creds_supermicro
{
    meta:
        id = "2laXEXXtZwOAHAQQ1hi2Oa"
        fingerprint = "fd0594f66d645dfdbb33c66f7bec23b72c1d427729ef1559a5bb7b7707ee96cf"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supermicro."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
    $a2="11a01c4a0f2f228796c93fa0ca1a634d"
    $a3="11a01c4a0f2f228796c93fa0ca1a634d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
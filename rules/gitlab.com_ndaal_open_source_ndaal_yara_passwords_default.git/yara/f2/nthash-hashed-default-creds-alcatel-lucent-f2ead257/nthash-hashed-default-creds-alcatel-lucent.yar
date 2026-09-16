rule nthash_hashed_default_creds_alcatel_lucent
{
    meta:
        id = "7Zhx0ZB2xaOrUVLm3MRUhk"
        fingerprint = "2aba715ecf74dd7a64949e10d8c1c28673873b59f71b9696ab12761c6210eb11"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alcatel_lucent."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c66b5e86f632994f72b202ca4ec9af9c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
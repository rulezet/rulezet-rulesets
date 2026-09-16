rule nthash_hashed_default_creds_entrust
{
    meta:
        id = "1mjap7O7JWzhrg6laDzcY4"
        fingerprint = "11b8a5762f8cc1ac84a9bafef4135b53385b21fe9ced7531fd96f0ece31979fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for entrust."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="ea352058987e8e853db21ae8d29d61e5"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
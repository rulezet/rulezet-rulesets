rule nthash_hashed_default_creds_juniper
{
    meta:
        id = "Jh8nHwLSaQ01aJL1oC4gD"
        fingerprint = "04f626d36d5f0b80c3f63dce043fc77f52b0d99ee7015b9c3f90c36a6f3d734f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e41364f3191d288dceef6373c3b40634"
    $a1="e41364f3191d288dceef6373c3b40634"
    $a2="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a3="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a4="f9e37e83b83c47a93c2f09f66408631b"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e41364f3191d288dceef6373c3b40634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="adf8b4f972a0854e849d74d83502821e"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="e168ab4ba7f72029ff07a6c3e45d2738"
    $a11="e168ab4ba7f72029ff07a6c3e45d2738"
    $a12="84956d35b03d4d733676d520d61b59d1"
    $a13="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
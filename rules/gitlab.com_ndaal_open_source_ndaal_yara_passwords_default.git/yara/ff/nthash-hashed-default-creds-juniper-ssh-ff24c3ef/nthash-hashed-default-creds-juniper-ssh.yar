rule nthash_hashed_default_creds_juniper_ssh
{
    meta:
        id = "aYZIOvcTG6r5NKpkBQu9C"
        fingerprint = "9fe08ddf432bd12671d1323810fb3456a4012ee83e6d6a5150056c7dbe16a322"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9e37e83b83c47a93c2f09f66408631b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="e41364f3191d288dceef6373c3b40634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="adf8b4f972a0854e849d74d83502821e"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e41364f3191d288dceef6373c3b40634"
    $a7="e41364f3191d288dceef6373c3b40634"
    $a8="e168ab4ba7f72029ff07a6c3e45d2738"
    $a9="e168ab4ba7f72029ff07a6c3e45d2738"
    $a10="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a11="9f6f7eb38fb0f133107a6ef02a2a2a94"
    $a12="84956d35b03d4d733676d520d61b59d1"
    $a13="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
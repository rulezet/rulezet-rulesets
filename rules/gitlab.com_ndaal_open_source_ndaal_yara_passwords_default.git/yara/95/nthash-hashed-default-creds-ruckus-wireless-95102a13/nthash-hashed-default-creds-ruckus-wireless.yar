rule nthash_hashed_default_creds_ruckus_wireless
{
    meta:
        id = "1a1Kn7Ps4s5KdaDhomPSR7"
        fingerprint = "a62d35a570568aa2ea8b7a8b2bf6bd9799f95ada999e3d9f55ffbd585228b522"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3305662ce54c2b07e0b64d22f0c769c"
    $a1="fad2607eda55ca3ecf8d89067ee91f84"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="f3305662ce54c2b07e0b64d22f0c769c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
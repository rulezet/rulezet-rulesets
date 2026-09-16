rule nthash_hashed_default_creds_endress_hauser
{
    meta:
        id = "50cH7JJy2QoOiWGABWzvEF"
        fingerprint = "8551108c4e6040db0320a3a2e83835d60e2604f39bf294ce75f0c8fbb81e1f65"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for endress_hauser."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fad2607eda55ca3ecf8d89067ee91f84"
    $a1="fad2607eda55ca3ecf8d89067ee91f84"
    $a2="ea7c23f2efca850e3fb547ca12567c33"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
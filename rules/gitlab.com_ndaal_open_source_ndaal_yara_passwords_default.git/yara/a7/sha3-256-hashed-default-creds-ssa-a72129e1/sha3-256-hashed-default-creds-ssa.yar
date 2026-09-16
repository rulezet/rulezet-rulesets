rule sha3_256_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
    $a1="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
condition:
    ($a0 and $a1)
}
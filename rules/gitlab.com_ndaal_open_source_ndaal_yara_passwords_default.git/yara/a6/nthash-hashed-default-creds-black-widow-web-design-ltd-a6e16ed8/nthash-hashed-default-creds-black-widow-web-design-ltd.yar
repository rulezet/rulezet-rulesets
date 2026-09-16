rule nthash_hashed_default_creds_black_widow_web_design_ltd
{
    meta:
        id = "6NqpVq19tYF7e9DlBNtCxM"
        fingerprint = "57c6153b52f9b04020e448bbcf4b09c45007408e478229462b9d5b170cf8363b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for black_widow_web_design_ltd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="961493c3ef0d6581e9acfbb8ba2090a2"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
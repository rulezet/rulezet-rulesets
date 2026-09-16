rule sha3_384_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c47a2b5caa3bd7d18d6e5be62fb501a5521b12fa2f6e8e1b45b9e504c3fcc3d19d7593aaea7caa3744f2d8df5360b82"
    $a1="2c3faca0bb3ca624815393ff6e5f233fe6385761df9bff7f97f4fc9ce3760b4838c5cce80e53805972a2d6ff21fb5daf"
condition:
    ($a0 and $a1)
}
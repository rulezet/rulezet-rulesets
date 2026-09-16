rule sha1_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
    $a1="6f6c2c83a731a9f1542a4afbb45ea0439c4f45ca"
    $a2="ff6aa9f2d161f0f4fae842235634129674aa22e8"
    $a3="c99df39e78f95ccbf4d3fc7d212a0fa5ad90742a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
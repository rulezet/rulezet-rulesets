rule sha3_224_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45f7d7ea8ed0aa7402864b27a4411e906b09d3ab302d2c8f0b0a1309"
    $a1="a55bddffa65a6b6e581a822306c116b1c4c2c683736d1f93c7890eee"
condition:
    ($a0 and $a1)
}
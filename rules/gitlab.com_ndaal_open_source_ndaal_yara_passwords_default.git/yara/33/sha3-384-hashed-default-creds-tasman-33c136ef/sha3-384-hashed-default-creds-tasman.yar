rule sha3_384_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1017e4c1bac9403628b270ab4adfbe211edb2c6a47b5a51cdc3bb1ba5ff5fd700846c80ecda74e5c9ef7d5eda716034d"
    $a1="186754002af123da7918dd8976c2040520afe3372cd348fa34a9e6bc501ceb06acad0455e1b09f944f952cf304b07984"
condition:
    ($a0 and $a1)
}
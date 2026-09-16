rule md5_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fedb09f0f5da90e577784e5f9fdc23"
    $a1="99fedb09f0f5da90e577784e5f9fdc23"
    $a2="293c9ea246ff9985dc6f62a650f78986"
    $a3="293c9ea246ff9985dc6f62a650f78986"
    $a4="4a05015d71f045770d4f59704146fe2d"
    $a5="4a05015d71f045770d4f59704146fe2d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
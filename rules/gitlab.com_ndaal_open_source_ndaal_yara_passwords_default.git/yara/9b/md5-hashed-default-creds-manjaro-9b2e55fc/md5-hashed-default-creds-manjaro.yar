rule md5_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8c81e359aba8242e2f65b872e2c67f5"
    $a1="8fbb65d5340a3da99b49da4a584f42bd"
    $a2="8a98be195c86c2857cc4185af53e3c86"
    $a3="8fbb65d5340a3da99b49da4a584f42bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
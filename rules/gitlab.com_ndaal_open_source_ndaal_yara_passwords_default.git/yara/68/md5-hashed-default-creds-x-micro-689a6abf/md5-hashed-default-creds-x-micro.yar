rule md5_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b3231655cebb7a1f783eddf27d254ca"
    $a1="1b3231655cebb7a1f783eddf27d254ca"
    $a2="77f959f119f4fb2321e9ce801e2f5163"
    $a3="77f959f119f4fb2321e9ce801e2f5163"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
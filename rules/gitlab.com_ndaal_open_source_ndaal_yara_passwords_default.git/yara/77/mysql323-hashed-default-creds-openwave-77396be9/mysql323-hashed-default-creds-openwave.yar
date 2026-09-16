rule mysql323_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46df46567aa9486a"
    $a1="05fc52e171381569"
    $a2="029e84b12ae29bc7"
    $a3="789bbd8d262f3ba1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
rule sha1_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe96dd39756ac41b74283a9292652d366d73931f"
    $a1="fe96dd39756ac41b74283a9292652d366d73931f"
    $a2="824f601c2a81ee6bab79ccd4792304c738d17630"
    $a3="824f601c2a81ee6bab79ccd4792304c738d17630"
    $a4="fe96dd39756ac41b74283a9292652d366d73931f"
    $a5="824f601c2a81ee6bab79ccd4792304c738d17630"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
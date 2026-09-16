rule mysql323_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fa040a5753d7bff"
    $a1="0fa040a5753d7bff"
    $a2="14c9a84f79f113de"
    $a3="56f0ba792e07d2c5"
    $a4="6d6608be5e6f7fa3"
    $a5="6d6608be5e6f7fa3"
    $a6="6af6992c7e70f8d5"
    $a7="6af6992c7e70f8d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
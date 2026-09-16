rule mysql41_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3792637D0995C22FC1AEF939DA506C5011EF2856"
    $a1="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a2="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a3="*87ECE1144502DFB74FD0B26A847683674C484658"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
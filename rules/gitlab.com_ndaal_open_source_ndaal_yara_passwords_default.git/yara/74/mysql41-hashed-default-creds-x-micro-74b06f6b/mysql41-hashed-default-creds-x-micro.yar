rule mysql41_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
    $a1="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
    $a2="*B0A1CB25F1A93EA332EEF05A8AF21365159E8CF9"
    $a3="*B0A1CB25F1A93EA332EEF05A8AF21365159E8CF9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
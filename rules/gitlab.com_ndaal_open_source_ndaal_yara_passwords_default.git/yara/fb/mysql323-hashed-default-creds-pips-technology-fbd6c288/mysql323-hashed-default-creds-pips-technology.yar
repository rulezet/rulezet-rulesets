rule mysql323_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cf672dc63c42510"
    $a1="4cf672dc63c42510"
    $a2="639dacf14112dca6"
    $a3="639dacf14112dca6"
    $a4="4096c0030b1b8446"
    $a5="4096c0030b1b8446"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
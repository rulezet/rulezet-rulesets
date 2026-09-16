rule mysql41_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a1="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a2="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a3="*F633E2398726B49F21C79F5C81B6BFF6E4F2F1B9"
    $a4="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a5="*DB915A0C6B3B228C1BFBBFB1CF119883882D2709"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
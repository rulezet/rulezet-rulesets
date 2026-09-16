rule mysql41_hashed_default_creds_integrated_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for integrated_networks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*84AAC12F54AB666ECFC2A83C676908C8BBC381B1"
    $a3="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a4="*23D21C4090DC4B3AD218DE058AFE02E9E3C89301"
    $a5="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
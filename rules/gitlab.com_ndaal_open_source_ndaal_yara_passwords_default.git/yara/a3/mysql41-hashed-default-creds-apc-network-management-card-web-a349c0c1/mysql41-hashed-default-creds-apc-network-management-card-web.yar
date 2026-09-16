rule mysql41_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a1="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a2="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a3="*61342F052E319D36B0E6C984AF680C4087210453"
    $a4="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a5="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
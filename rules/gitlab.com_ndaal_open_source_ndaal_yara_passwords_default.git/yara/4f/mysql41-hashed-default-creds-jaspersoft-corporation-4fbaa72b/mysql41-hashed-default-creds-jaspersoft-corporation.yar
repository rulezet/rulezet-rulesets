rule mysql41_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a1="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a2="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a3="*87ECE1144502DFB74FD0B26A847683674C484658"
    $a4="*76C8E1C84DD7956527CE195BA7EF594B8F9B8854"
    $a5="*76C8E1C84DD7956527CE195BA7EF594B8F9B8854"
    $a6="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a7="*F5AB3475E4D0309381498567B7C7A270ADED2652"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
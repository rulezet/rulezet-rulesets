rule mysql41_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a1="*965E9F326E96D0343097F671E837ED989280EA35"
    $a2="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a3="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a4="*C71FE3464BF650F5208E4808638BE6B9B9C43959"
    $a5="*C697E2251DECB7B86232C38189F493FC2FEF614A"
    $a6="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a7="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a8="*E8D8551D13D1FAAC2031110193B72187230180FE"
    $a9="*61342F052E319D36B0E6C984AF680C4087210453"
    $a10="*61342F052E319D36B0E6C984AF680C4087210453"
    $a11="*61342F052E319D36B0E6C984AF680C4087210453"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}
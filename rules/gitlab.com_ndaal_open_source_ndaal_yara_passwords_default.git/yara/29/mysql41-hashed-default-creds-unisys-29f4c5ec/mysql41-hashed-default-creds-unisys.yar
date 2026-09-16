rule mysql41_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*81A52AB76BBAB3CCC39A8E901EAD6DDE36816800"
    $a1="*81A52AB76BBAB3CCC39A8E901EAD6DDE36816800"
    $a2="*EEB2C23B211C495171057FC35828DEFD8F521AD1"
    $a3="*EEB2C23B211C495171057FC35828DEFD8F521AD1"
    $a4="*2097E81CF119F49F3B5AF986EA5BD8D6D96D771B"
    $a5="*2097E81CF119F49F3B5AF986EA5BD8D6D96D771B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
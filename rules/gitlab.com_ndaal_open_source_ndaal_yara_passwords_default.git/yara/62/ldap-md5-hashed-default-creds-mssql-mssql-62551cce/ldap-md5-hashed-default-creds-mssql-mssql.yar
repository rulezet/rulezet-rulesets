rule ldap_md5_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}CifraEgCv9iWO0Ug81wIKw=="
    $a1="{MD5}ozmrt50wB+rIYTekYPMsng=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a4="{MD5}QvdJref54ZW/R183pEyvyw=="
    $a5="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a6="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a7="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
    $a8="{MD5}DAE0wMvr9IvoyVkg9ep0/A=="
    $a9="{MD5}wS4B8qE/9Vh+Hp5K7bgkLQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
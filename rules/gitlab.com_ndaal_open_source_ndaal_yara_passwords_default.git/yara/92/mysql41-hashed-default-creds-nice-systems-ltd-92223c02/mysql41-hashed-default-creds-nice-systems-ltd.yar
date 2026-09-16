rule mysql41_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9E559E45CFC52B90C1944EF4A5CBCD5E04D7098F"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*9E559E45CFC52B90C1944EF4A5CBCD5E04D7098F"
    $a3="*E3C93FB472B2F6FE47784E63D1451FE4E37D3703"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
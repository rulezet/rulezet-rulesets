rule blake2b_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dcfdfac6ba0ae53b9b8b5afdd7d9630efaefa495b094c02c93af898c09431bf0e73a27d46e14996a4645658b1bcb2917b4d5183475332f719435fe83ad3c932"
    $a1="46f1d97852823c7e52ad4594d2b90cc2872d20578aca45692ff66b31f836a4fe2f214ed485429eee8dd72894a87f659fcf60b0f1462d202f0a00f8ae6d80b08d"
condition:
    ($a0 and $a1)
}
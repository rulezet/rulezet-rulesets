rule mysql323_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ccf30087d4af054"
    $a1="5faa43c3601964be"
    $a2="0ccf30087d4af054"
    $a3="0ccf30087d4af054"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
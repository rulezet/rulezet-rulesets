rule mysql41_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3C84F49217E2D08023FB84C4A19E619868D6217A"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a3="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
rule mysql41_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FB4AFEF39A92B3AA01F1B9A8F5E3D1F8D8E72271"
    $a1="*27BB56C3DEDB0B94CE76541B778028B1A46FE746"
condition:
    ($a0 and $a1)
}
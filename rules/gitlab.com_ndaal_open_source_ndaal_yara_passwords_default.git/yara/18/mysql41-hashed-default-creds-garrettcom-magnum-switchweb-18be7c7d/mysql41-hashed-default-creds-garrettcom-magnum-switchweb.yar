rule mysql41_hashed_default_creds_garrettcom_magnum_switchweb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for garrettcom_magnum_switchweb."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a1="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
condition:
    ($a0 and $a1)
}
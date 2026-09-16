rule ldap_md5_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a1="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a2="{MD5}EdjCimRJCph2EvIzJQJGfw=="
    $a3="{MD5}EdjCimRJCph2EvIzJQJGfw=="
    $a4="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a5="{MD5}EdjCimRJCph2EvIzJQJGfw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
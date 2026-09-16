rule ldap_md5_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Z088LBqKb5BGHopm+1VQug=="
    $a1="{MD5}wrp+eFxJBQ9I2pqsxFwrhQ=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
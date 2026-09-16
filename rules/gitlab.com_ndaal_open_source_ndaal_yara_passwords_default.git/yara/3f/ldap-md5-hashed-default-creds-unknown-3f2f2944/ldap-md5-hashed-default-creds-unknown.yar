rule ldap_md5_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}efFT+Ips3PJfWsui+w98jg=="
    $a1="{MD5}efFT+Ips3PJfWsui+w98jg=="
    $a2="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a3="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a4="{MD5}CY9rzUYh03PK3k6DJie09g=="
    $a5="{MD5}CY9rzUYh03PK3k6DJie09g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
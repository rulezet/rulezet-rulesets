rule ldap_md5_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}hU82xwm2YvU8AOosEaQPeg=="
    $a1="{MD5}5kie58VU+u9E3DJOEQ81lQ=="
    $a2="{MD5}ainPGBYfZSqw4LKUMknFLg=="
    $a3="{MD5}wRdCB4ArmsWOrLV+Z/67aA=="
    $a4="{MD5}f5A9hEtRdXRYTIZpqWMifw=="
    $a5="{MD5}B7RnLF8d5ULCw4M6pcbMwA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
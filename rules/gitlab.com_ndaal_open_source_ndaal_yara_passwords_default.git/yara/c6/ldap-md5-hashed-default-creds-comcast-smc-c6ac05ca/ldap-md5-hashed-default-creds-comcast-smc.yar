rule ldap_md5_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Zn+Qud3uIEnNJ2hevxDbkA=="
    $a1="{MD5}JXwtGgQjpqfBCGMqj5Y5Mg=="
    $a2="{MD5}lH8BMxqw2xsIak/JHnvakw=="
    $a3="{MD5}JXwtGgQjpqfBCGMqj5Y5Mg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
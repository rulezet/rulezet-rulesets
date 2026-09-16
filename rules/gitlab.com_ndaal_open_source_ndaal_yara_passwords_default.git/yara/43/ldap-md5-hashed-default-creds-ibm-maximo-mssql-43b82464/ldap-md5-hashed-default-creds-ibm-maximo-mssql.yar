rule ldap_md5_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}z8OIE+4vldJSdzcH11Rm+A=="
    $a1="{MD5}z8OIE+4vldJSdzcH11Rm+A=="
    $a2="{MD5}vwkNQ11A/dpRQMTsZWcDRA=="
    $a3="{MD5}vwkNQ11A/dpRQMTsZWcDRA=="
    $a4="{MD5}lRrFZY79hzKjPG4vxWiFag=="
    $a5="{MD5}lRrFZY79hzKjPG4vxWiFag=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
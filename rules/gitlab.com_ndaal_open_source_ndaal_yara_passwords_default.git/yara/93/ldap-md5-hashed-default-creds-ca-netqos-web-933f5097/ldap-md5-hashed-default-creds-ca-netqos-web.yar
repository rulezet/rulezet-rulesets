rule ldap_md5_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}DL5E406h6vjueq1/f2DjNw=="
    $a1="{MD5}VTGIrLrt+ehNPigCw5lyCg=="
    $a2="{MD5}DL5E406h6vjueq1/f2DjNw=="
    $a3="{MD5}i1HLw2qg2vnLEwXD57FJ2A=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
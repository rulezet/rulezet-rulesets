rule ldap_md5_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}xMpCOKC5I4INzFCab3WEmw=="
    $a1="{MD5}5ToSwauciU0YPOC1deT+9Q=="
    $a2="{MD5}xMpCOKC5I4INzFCab3WEmw=="
    $a3="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
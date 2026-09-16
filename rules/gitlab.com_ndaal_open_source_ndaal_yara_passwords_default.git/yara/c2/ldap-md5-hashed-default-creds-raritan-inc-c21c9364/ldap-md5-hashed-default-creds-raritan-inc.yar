rule ldap_md5_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ipE6QEP9vsdW779R2U5MyQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ipE6QEP9vsdW779R2U5MyQ=="
    $a3="{MD5}QESNt1EP/7bi/naR9fuRtg=="
    $a4="{MD5}+6Dc72H70CaC3wlv0J7Zcg=="
    $a5="{MD5}e5jTXEF08d44lUKHjRBCfQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
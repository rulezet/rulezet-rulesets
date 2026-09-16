rule ldap_md5_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}DYUbGMExPHaycx+xvKU6+A=="
    $a1="{MD5}DYUbGMExPHaycx+xvKU6+A=="
    $a2="{MD5}wh+Wm18D0z1D4E+PE252gg=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}ZX+LjaYo74PPaRAbaBcVCg=="
    $a5="{MD5}aQkOGqj1OXq0G++QdIFsyA=="
    $a6="{MD5}ubg7rWvStPfEAQkwTPWA4Q=="
    $a7="{MD5}ubg7rWvStPfEAQkwTPWA4Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
rule ldap_md5_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}tQQwEJL7/iHGon+IdoRDvQ=="
    $a2="{MD5}PS5r3tBGyi4/kG8EI1snmw=="
    $a3="{MD5}tQQwEJL7/iHGon+IdoRDvQ=="
    $a4="{MD5}t71lNr+bMHHGQnGMelFOrA=="
    $a5="{MD5}tQQwEJL7/iHGon+IdoRDvQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
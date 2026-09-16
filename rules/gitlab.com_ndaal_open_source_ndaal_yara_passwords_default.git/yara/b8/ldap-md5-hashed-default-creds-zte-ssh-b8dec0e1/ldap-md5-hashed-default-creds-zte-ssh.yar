rule ldap_md5_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}7StcATnOyK0oc4KdwRF9UA=="
    $a3="{MD5}7StcATnOyK0oc4KdwRF9UA=="
    $a4="{MD5}z5ce4X1XH8H/pDamh2LDgQ=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}DsN3KoM27N3WtsYfAcBSRA=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a9="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a10="{MD5}3paPsOthPZm+Aa59PX07AQ=="
    $a11="{MD5}3paPsOthPZm+Aa59PX07AQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}
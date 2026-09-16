rule ldap_md5_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}Q0mQyKJdK+lIY1Ya6YvWgg=="
    $a5="{MD5}Q0mQyKJdK+lIY1Ya6YvWgg=="
    $a6="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}gnzLDuqKcGxMNKFokfhOew=="
    $a9="{MD5}7Tah73alnuPxUYDgRBGIrQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
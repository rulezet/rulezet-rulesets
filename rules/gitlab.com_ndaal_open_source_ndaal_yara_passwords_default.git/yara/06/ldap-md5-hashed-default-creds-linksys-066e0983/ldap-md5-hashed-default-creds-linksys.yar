rule ldap_md5_hashed_default_creds_linksys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}FcmQBpcoZ/SdIs3bNmjJIQ=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a5="{MD5}2LWPe/ziju/MHN1blcO2Yw=="
    $a6="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a7="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a8="{MD5}aSV2hlja6T/3KqB8v9TWTA=="
    $a9="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
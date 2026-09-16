rule ldap_md5_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}Gp3/FfmBUEQhdCcaIj0B5A=="
    $a3="{MD5}ful1KyzIz3kWaHPaE0rHYQ=="
    $a4="{MD5}A58rrK0kWjWcyI9Dv0u9Pw=="
    $a5="{MD5}XamHRzlzqZbzA9zPowgWDw=="
    $a6="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a7="{MD5}N94k1EAoWljYbmg5o+sqzQ=="
    $a8="{MD5}BIwhtxE3rZeIYLfmfl9pwA=="
    $a9="{MD5}ZAD974uH7d5GcUV4+LWocg=="
    $a10="{MD5}yVw22qFylsYxfz/Gdd42CA=="
    $a11="{MD5}womC9SZCF8ms+rIxR77+MA=="
    $a12="{MD5}B4SqWGXY+/9Roq3UX53gUg=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}TLnIqASP0CKUR3/LGkEZGg=="
    $a15="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a16="{MD5}aFPVAdlva/HiUp6mfyMyOQ=="
    $a17="{MD5}scW+mNfojBlkeKGVvZzJNA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}
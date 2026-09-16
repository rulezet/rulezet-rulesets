rule ldap_md5_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}eUhBShBvh1iBdOl4eOqHaA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a3="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a4="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}C6944Nyt1RJfu2rlBRSz5w=="
    $a7="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a8="{MD5}KE8rCIqNiJl6KT4C6YDh3w=="
    $a9="{MD5}CxgAeNmUyyte2J186Ofuog=="
    $a10="{MD5}eUhBShBvh1iBdOl4eOqHaA=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}
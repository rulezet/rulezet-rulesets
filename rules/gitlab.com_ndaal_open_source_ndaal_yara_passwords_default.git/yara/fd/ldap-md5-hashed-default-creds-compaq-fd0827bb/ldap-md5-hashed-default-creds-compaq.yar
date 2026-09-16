rule ldap_md5_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}HslET/NiE+zDEIwRxjOX6A=="
    $a3="{MD5}VccJjudQkN+zuRN/zzW6zA=="
    $a4="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a5="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a6="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a7="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a8="{MD5}TJGE83z/AbzcMtxIbsNpYQ=="
    $a9="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a10="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a11="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a12="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}lsqdL5S4ceaTO1GADiTpFw=="
    $a15="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}
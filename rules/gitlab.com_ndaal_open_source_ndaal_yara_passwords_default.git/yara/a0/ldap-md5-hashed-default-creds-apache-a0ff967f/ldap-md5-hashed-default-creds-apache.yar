rule ldap_md5_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4cdZrdC/qII4ehvFazHo5A=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a7="{MD5}KafpZGe2mp9akzMuKemw3g=="
    $a8="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a9="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a10="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a11="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a12="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}klrSZ5sJWBbPwM93L0ZyKQ=="
    $a15="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a16="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a17="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a18="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a19="{MD5}9ss+gWSWUo1Bh9tTvGZWfw=="
    $a20="{MD5}GzWdh1OFi1W++gRBBnqu0w=="
    $a21="{MD5}MbhktVRpE92SiklBahC60Q=="
    $a22="{MD5}cUs5P0ssKVYdRMXgqQ/9uQ=="
    $a23="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}
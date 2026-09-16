rule ldap_md5_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}s9l3hM0IpgMd6CR4axhmZw=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}KieGd0pXIP/gg8NNyFpIAw=="
    $a9="{MD5}/ZancD9nCrs/QkmAz9C1Og=="
    $a10="{MD5}TJGE83z/AbzcMtxIbsNpYQ=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}YDQ3NidDblyd8K4SKRctSw=="
    $a13="{MD5}YDQ3NidDblyd8K4SKRctSw=="
    $a14="{MD5}DqvOwcCOmIozJ73DmVr2rQ=="
    $a15="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a16="{MD5}oB6adgnk9xfhMcrqaYl24A=="
    $a17="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a18="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a19="{MD5}qV5bkHOCOQo1on//kl8VpA=="
    $a20="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a21="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}
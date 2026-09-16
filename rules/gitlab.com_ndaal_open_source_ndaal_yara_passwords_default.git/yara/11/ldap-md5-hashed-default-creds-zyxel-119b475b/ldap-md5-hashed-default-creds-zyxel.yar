rule ldap_md5_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a3="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a4="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a5="{MD5}rda7WOE5vhAzJNBNgtj1RQ=="
    $a6="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}cQ2mTEFA2qgoUgLVWIy8rw=="
    $a9="{MD5}5hXhhtPV+MrZG3sMyBs0eQ=="
    $a10="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a11="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a12="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a13="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a14="{MD5}Sn0e1BRHTkAzrCnMuGU9mw=="
    $a15="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a16="{MD5}eeiSMr6y40SmMpTfpR5LEw=="
    $a17="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}
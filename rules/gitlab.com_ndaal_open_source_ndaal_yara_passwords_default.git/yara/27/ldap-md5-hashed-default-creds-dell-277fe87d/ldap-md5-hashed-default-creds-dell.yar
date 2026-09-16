rule ldap_md5_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}5uZriYHBAw1WUNoVnnlTmg=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}FrDNfya/tj2l7ahwyUHLvQ=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}06kZTHb7wRTQrhFRW6TzJQ=="
    $a9="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a10="{MD5}KCBaGi2Tkn+1g306SIKe9w=="
    $a11="{MD5}m5OhlqyB1VgseCL7+FsbJQ=="
    $a12="{MD5}4nwkeZPtqWajBHK5Vq7/vw=="
    $a13="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a14="{MD5}eNHkcN0qQ9n/TuzZO/m6jQ=="
    $a15="{MD5}xqM5EcxT35vbhKrI2GoFZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}
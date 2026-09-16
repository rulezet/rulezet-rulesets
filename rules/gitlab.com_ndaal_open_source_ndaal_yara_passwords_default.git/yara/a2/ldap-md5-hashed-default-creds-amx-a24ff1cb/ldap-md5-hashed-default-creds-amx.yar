rule ldap_md5_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}nXMRukWfnkXtdGdVoy3NEQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a4="{MD5}6EJ5Wygik/1hvClMSe2xKw=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a7="{MD5}bFYFFNzBj5wxv8HV0pp6oA=="
    $a8="{MD5}nXMRukWfnkXtdGdVoy3NEQ=="
    $a9="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a10="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a11="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a12="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a13="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a14="{MD5}PpWzXfFNh5/v2gzNCJdERg=="
    $a15="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}
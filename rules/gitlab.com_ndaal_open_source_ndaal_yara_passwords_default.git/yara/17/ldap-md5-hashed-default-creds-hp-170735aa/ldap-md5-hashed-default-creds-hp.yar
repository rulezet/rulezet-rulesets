rule ldap_md5_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}tfx89xdTET10OEnsvNpD2A=="
    $a3="{MD5}62HurZDjuJnGvL4nrFgWYA=="
    $a4="{MD5}sULxoIkFuJnBsWuS/IM/9w=="
    $a5="{MD5}C8TA5L87Pmnz8JFgCEoSDg=="
    $a6="{MD5}9nDHOCF+4M/UaQQFzzLHuw=="
    $a7="{MD5}C8TA5L87Pmnz8JFgCEoSDg=="
    $a8="{MD5}gI111mh8j085io01pRMHbQ=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}CZ6+pI6pZmp9ohdyZ5gxOA=="
    $a11="{MD5}HG6YDg7uc6mpUSQ59WZlxQ=="
    $a12="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a13="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a14="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a15="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a16="{MD5}0NUPv2NgfJPsKfUVrE5YDA=="
    $a17="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}
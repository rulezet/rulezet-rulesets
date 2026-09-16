rule ldap_md5_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}eJRv+w4/1+9OD+zpQvZXWQ=="
    $a5="{MD5}dk3p8Ck9OyLcgK/mdnn7sw=="
    $a6="{MD5}eJRv+w4/1+9OD+zpQvZXWQ=="
    $a7="{MD5}jexwDac+AsQEpISxbUyq0g=="
    $a8="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a9="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a10="{MD5}3Ph/M7pPh2zvdoHBdwW0kA=="
    $a11="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a12="{MD5}Epri2wsP8Fi50Y6qR/M7qg=="
    $a13="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
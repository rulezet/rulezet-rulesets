rule ldap_md5_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}ICy5YqxZB1uWSwcVLSNLcA=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}KTecJk2ZZzcAlMLlz0nd6g=="
    $a7="{MD5}KYStecWadFHdgccTrCc9Xw=="
    $a8="{MD5}aX76lK0eZlxNDt1MgQ22+w=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a10="{MD5}M6bpxI16LfevqlsK/M7HpQ=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a12="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a13="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
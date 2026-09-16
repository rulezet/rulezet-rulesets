rule ldap_md5_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}gdyb21LQTcIANtvYMT7QVQ=="
    $a1="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a2="{MD5}L2zlFbIuoPMh6LgUvh9rsA=="
    $a3="{MD5}EDarKEjBfZLQQz6M6Y6QOg=="
    $a4="{MD5}IwUv4/W8Yn0VTYWO+0ChZQ=="
    $a5="{MD5}g3Ep/M66Gf6H5MEkT/oHIQ=="
    $a6="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a7="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a8="{MD5}tg64O/Uz7s8b3mWUCSWpgQ=="
    $a9="{MD5}oKAsIqigXNp7QNzmfNbmIg=="
    $a10="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}
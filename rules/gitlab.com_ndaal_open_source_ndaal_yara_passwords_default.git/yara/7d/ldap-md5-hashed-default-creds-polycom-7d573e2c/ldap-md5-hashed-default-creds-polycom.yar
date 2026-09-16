rule ldap_md5_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}JQz4tRx3Pz+NyLS+hnqaAg=="
    $a1="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a2="{MD5}HRHVw9n3RRlIbSmEVDPSnw=="
    $a3="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a4="{MD5}LSuWRi0CnPuWw70YVjT5bQ=="
    $a5="{MD5}IAzrJoB9a/mf1vTw0cpU1A=="
    $a6="{MD5}BC5K99ylzQk90ecXdeRR4A=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}77E8XZK2QaEEI0AcB0UGHw=="
    $a9="{MD5}g0YipBPjxCwt2AgMImvuhQ=="
    $a10="{MD5}JQz4tRx3Pz+NyLS+hnqaAg=="
    $a11="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}
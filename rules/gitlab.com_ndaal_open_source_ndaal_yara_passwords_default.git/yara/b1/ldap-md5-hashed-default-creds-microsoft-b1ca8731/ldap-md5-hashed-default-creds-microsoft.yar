rule ldap_md5_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a1="{MD5}NeHOrKb0JdyHohJfVZ9NbQ=="
    $a2="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a5="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a6="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a7="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a8="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a9="{MD5}rbgxp/3YPdHiownOdZHf+A=="
    $a10="{MD5}NOAZHCAXKQ9VWl2d+I5njA=="
    $a11="{MD5}NOAZHCAXKQ9VWl2d+I5njA=="
    $a12="{MD5}yAKykVorUiGV8K9TgD8rGw=="
    $a13="{MD5}ldcCszJrq/UZ3P98uSCvRw=="
    $a14="{MD5}PcJv4xwCmWHTaBEZPmnJGQ=="
    $a15="{MD5}PcJv4xwCmWHTaBEZPmnJGQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}
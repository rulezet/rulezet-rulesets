rule ldap_md5_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a1="{MD5}oPhIlCzoY89TwPpsxoQAfQ=="
    $a2="{MD5}nOIdjzmS2JoyWqnc9SClkQ=="
    $a3="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
    $a4="{MD5}oyw9POwg9aCVlbhX5FtHfw=="
    $a5="{MD5}lvmWPiVSCpARyCQBkgeU8A=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
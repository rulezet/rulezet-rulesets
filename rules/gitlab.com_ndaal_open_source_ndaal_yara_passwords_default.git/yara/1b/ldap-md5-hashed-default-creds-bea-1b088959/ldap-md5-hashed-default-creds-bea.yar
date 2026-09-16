rule ldap_md5_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a1="{MD5}j/MkifkvM0FmlL6P3C1MIg=="
    $a2="{MD5}6R5jSBV4aN6d2LJcga6/uQ=="
    $a3="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a4="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a5="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
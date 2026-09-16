rule ldap_md5_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a1="{MD5}EAuMrXzypW9t948XH5eh7A=="
    $a2="{MD5}epW/kmoDM/V3Ba6sB6Niog=="
    $a3="{MD5}SKNltM4eMipVrpAX89rwwA=="
    $a4="{MD5}nfOwHGDfINE4Q4Qf8NRILA=="
    $a5="{MD5}1WtpmDDne6U4VWecsdJS2g=="
    $a6="{MD5}epW/kmoDM/V3Ba6sB6Niog=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
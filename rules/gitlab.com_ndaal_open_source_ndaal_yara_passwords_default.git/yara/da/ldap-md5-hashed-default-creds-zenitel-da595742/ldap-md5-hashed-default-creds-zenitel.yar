rule ldap_md5_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Kwk5pdDTWTsJRcoQiQXEHA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}/307iNDHld4ntZ+cJF3/og=="
    $a3="{MD5}c6zZpZchMLdQZsgllaH64w=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
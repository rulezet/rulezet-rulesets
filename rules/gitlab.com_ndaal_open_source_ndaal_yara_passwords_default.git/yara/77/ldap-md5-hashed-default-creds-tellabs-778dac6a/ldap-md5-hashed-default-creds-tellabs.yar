rule ldap_md5_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}p9DnqXdFb2CqNnBqzH9ftQ=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}iVRGLcBtEjSOKtMvTqjSXw=="
    $a3="{MD5}Lx6a5+ai+XohwZ/kwwB6VA=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
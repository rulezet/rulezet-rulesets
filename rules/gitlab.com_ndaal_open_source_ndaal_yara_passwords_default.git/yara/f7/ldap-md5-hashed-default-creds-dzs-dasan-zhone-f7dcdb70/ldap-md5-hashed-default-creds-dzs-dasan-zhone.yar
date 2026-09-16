rule ldap_md5_hashed_default_creds_dzs___dasan_zhone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dzs___dasan_zhone."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a1="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
condition:
    ($a0 and $a1)
}
rule ldap_md5_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}UZOStnpHAtwT5C5iEHKjhg=="
    $a1="{MD5}5sgw3FwvcFUl0T+xyJVz8g=="
condition:
    ($a0 and $a1)
}
rule ldap_md5_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}hdRUiLIQxijggW8UbrgJtA=="
    $a1="{MD5}nYLQXMCX+WbiawywvWu+Kw=="
    $a2="{MD5}fnAKFl33Z0ZTCQO6Tyki2Q=="
    $a3="{MD5}9IbAADrcwhvx7SUGflqJ4Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
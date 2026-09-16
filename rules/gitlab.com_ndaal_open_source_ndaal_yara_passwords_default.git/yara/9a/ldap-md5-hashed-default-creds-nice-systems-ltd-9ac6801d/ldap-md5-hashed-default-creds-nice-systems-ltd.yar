rule ldap_md5_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}6o9F5wRJHLv7IGo+9ymzYw=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}6o9F5wRJHLv7IGo+9ymzYw=="
    $a3="{MD5}2gBtFrkSitmZBvWAh7OvKQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
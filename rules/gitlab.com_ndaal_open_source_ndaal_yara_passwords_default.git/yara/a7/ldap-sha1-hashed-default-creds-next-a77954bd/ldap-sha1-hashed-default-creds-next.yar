rule ldap_sha1_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}kVNYe8XF4gHz40mlgfAf4BQ7VMI="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}d0zumXD4EpKOl9vsi0a9GE1pDf0="
    $a3="{SHA}d0zumXD4EpKOl9vsi0a9GE1pDf0="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
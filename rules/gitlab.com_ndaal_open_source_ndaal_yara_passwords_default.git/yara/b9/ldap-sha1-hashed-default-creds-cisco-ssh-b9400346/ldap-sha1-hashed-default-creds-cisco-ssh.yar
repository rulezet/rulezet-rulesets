rule ldap_sha1_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a1="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a2="{SHA}eveMkR1bSL6h3CRJ2diVE6vrS+U="
    $a3="{SHA}mY58X88WgXOYXclPmaA3PsKy3zQ="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
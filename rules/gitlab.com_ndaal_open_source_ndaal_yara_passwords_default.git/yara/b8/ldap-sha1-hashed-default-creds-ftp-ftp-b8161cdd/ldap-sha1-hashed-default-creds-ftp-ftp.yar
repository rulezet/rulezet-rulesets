rule ldap_sha1_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dha7h70F9kOeNnK6GyvlXVvraLM="
    $a1="{SHA}dha7h70F9kOeNnK6GyvlXVvraLM="
    $a2="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a3="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
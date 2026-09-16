rule ldap_sha1_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}aEXG2QWFwk1j3iZsmm2gQJDtLcI="
    $a1="{SHA}aEXG2QWFwk1j3iZsmm2gQJDtLcI="
    $a2="{SHA}amBhnCWTmkU3STfQjOZ0OJ49d2U="
    $a3="{SHA}amBhnCWTmkU3STfQjOZ0OJ49d2U="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
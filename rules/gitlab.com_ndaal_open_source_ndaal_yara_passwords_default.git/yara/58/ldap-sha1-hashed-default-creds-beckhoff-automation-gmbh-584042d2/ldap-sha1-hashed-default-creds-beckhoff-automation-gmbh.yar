rule ldap_sha1_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}NWoZK3kTsExUV00Ywo1G5jlUKKs="
    $a1="{SHA}gdy31mOjsgl8ksO6WC653Y6ACWY="
    $a2="{SHA}NWoZK3kTsExUV00Ywo1G5jlUKKs="
    $a3="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
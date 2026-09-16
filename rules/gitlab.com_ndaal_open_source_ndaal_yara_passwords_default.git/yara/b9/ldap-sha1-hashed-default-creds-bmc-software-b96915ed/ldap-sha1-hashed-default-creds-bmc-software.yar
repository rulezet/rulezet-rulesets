rule ldap_sha1_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}YPObZyw3Z4czwHUbqVp9RFmk+iY="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}m9EcoiDQdHrb8YKlNsJKEnkMNqg="
    $a3="{SHA}9p50JrL0cxeLfwmwRTnsSTN/1yM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
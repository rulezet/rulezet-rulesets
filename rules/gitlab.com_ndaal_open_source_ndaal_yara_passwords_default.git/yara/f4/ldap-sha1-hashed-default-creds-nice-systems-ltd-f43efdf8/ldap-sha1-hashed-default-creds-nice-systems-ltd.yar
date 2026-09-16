rule ldap_sha1_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}q/hR6GL5WL5de0ovsSMkJJ6Okkk="
    $a1="{SHA}HtojdYvp425eDSpqh95YSqygGT8="
    $a2="{SHA}q/hR6GL5WL5de0ovsSMkJJ6Okkk="
    $a3="{SHA}vKHelGpBQGC4Z553hT2eMrxyHEU="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
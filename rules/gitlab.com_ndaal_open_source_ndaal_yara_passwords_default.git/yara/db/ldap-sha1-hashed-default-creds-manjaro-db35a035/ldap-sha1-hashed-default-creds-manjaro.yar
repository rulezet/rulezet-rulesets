rule ldap_sha1_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}HhzUUYpiYFe3j+B3UgoUyiLnOls="
    $a1="{SHA}/fu3HvphFfVB5GnPqbd/vUZLB7M="
    $a2="{SHA}oDov96UnKd659M0+LFBhGNC1Ux0="
    $a3="{SHA}/fu3HvphFfVB5GnPqbd/vUZLB7M="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
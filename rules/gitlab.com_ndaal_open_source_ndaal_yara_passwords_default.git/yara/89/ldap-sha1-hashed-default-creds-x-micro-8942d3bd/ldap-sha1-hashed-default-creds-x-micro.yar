rule ldap_sha1_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
    $a1="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
    $a2="{SHA}EERpD7c5YAn3MdElvRjmNP13rSg="
    $a3="{SHA}EERpD7c5YAn3MdElvRjmNP13rSg="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
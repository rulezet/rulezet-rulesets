rule ldap_sha1_hashed_default_creds_super_micro_computer_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for super_micro_computer_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}tSHKpuHbguWgHJJKQZhwy3K4FjU="
    $a1="{SHA}tSHKpuHbguWgHJJKQZhwy3K4FjU="
condition:
    ($a0 and $a1)
}
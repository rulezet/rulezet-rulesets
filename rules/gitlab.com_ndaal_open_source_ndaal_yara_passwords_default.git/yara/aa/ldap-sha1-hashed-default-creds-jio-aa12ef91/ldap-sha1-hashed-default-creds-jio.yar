rule ldap_sha1_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nXzE9Go4nRwJpCns/C3VxUaH2XM="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a3="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
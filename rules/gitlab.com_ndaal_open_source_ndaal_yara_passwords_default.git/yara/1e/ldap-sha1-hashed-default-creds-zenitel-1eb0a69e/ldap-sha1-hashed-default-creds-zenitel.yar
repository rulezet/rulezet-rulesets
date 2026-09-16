rule ldap_sha1_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}A0lKJO1TN6zR6/kCUuBFbDhAQK0="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}CC1n3GxopkWHFXPk8BgHu8KQDag="
    $a3="{SHA}tSHKpuHbguWgHJJKQZhwy3K4FjU="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
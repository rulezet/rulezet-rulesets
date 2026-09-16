rule ldap_sha1_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nHyUS6jhNLxpqRAYDWKVLJkFD48="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}nHyUS6jhNLxpqRAYDWKVLJkFD48="
    $a3="{SHA}Acgmegww93lvwu4KNa7FhaziQug="
    $a4="{SHA}nHyUS6jhNLxpqRAYDWKVLJkFD48="
    $a5="{SHA}bzcskIIvfech8+btxCZTp0boHZA="
    $a6="{SHA}nHyUS6jhNLxpqRAYDWKVLJkFD48="
    $a7="{SHA}DgphyGdhbu8UW8o2U7vQJAYDLcE="
    $a8="{SHA}nHyUS6jhNLxpqRAYDWKVLJkFD48="
    $a9="{SHA}h1qPL0LFcPX06nv9FU9YK8+VZzo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
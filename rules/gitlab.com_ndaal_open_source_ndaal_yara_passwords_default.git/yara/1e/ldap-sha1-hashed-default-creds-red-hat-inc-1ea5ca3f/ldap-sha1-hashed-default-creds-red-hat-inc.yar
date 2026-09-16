rule ldap_sha1_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
    $a3="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
    $a4="{SHA}IuocZJyClGqm5Hnh/9Mh5KMYsbA="
    $a5="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
rule ldap_sha1_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
    $a1="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
    $a2="{SHA}IuocZJyClGqm5Hnh/9Mh5KMYsbA="
    $a3="{SHA}sVNVsk7kZoCt9KY8X7RVDijNQEA="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
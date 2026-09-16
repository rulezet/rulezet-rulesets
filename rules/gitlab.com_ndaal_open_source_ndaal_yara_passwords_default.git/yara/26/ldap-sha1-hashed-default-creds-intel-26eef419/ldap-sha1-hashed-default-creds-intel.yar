rule ldap_sha1_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a1="{SHA}gEN6RKZh0UEXQgkRnVQSWlmmSyo="
    $a2="{SHA}buPCkHsxHwTv7Nn3NSkYqXCk/g0="
    $a3="{SHA}buPCkHsxHwTv7Nn3NSkYqXCk/g0="
    $a4="{SHA}7s3dENe9h9PXZb9lUEYFEXwC6i4="
    $a5="{SHA}7s3dENe9h9PXZb9lUEYFEXwC6i4="
    $a6="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}LITXpMlsPXb3srIYYau17DlCP20="
    $a9="{SHA}66CC/0VRfAa9Nlwv3h/HfNp6j28="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
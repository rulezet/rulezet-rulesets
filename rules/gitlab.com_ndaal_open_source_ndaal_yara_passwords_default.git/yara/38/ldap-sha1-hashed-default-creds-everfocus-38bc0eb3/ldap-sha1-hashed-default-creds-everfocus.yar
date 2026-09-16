rule ldap_sha1_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a3="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a4="{SHA}D00J5D0gjV6SIjIvvHCRzuoaeMM="
    $a5="{SHA}D00J5D0gjV6SIjIvvHCRzuoaeMM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
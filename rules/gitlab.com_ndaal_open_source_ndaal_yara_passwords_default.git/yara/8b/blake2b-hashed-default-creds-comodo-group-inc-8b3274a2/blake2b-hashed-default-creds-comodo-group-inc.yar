rule blake2b_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a9d933c41a6f459836041cea4dd353e2688f7dda5b16484ede305ee7dd49ae2d6db9ca413710c78d60d12d3184768e510b2dee87e242661fecccaff8883c75a"
    $a1="1a9d933c41a6f459836041cea4dd353e2688f7dda5b16484ede305ee7dd49ae2d6db9ca413710c78d60d12d3184768e510b2dee87e242661fecccaff8883c75a"
condition:
    ($a0 and $a1)
}
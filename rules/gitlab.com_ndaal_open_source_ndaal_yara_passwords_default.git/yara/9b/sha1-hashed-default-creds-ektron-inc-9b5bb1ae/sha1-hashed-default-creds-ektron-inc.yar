rule sha1_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="748a336cc88c03ccb07ed5f5073d18624731b8b5"
    $a1="748a336cc88c03ccb07ed5f5073d18624731b8b5"
    $a2="54f39b2b097190c7f817d09b71899db1c9febf5d"
    $a3="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
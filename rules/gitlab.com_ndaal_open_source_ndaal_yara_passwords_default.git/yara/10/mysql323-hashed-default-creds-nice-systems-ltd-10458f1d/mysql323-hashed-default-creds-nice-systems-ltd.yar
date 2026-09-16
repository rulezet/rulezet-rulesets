rule mysql323_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b75b4052eb863a3"
    $a1="58f7ee435f925abe"
    $a2="1b75b4052eb863a3"
    $a3="0f9a0e9f59b7cf36"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
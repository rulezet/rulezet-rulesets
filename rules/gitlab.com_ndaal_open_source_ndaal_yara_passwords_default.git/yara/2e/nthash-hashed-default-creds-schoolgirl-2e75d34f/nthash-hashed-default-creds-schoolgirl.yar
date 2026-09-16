rule nthash_hashed_default_creds_schoolgirl
{
    meta:
        id = "6YN87krQQtWnaDjQBBpdtd"
        fingerprint = "bff4dcb096febab80f67554b97175ba2cd0dd291449833038c54419075e66b47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8ee7b9bbd1c844655162e0923b7fc6e"
    $a1="3b491869048dae930cef429847d758c7"
condition:
    ($a0 and $a1)
}
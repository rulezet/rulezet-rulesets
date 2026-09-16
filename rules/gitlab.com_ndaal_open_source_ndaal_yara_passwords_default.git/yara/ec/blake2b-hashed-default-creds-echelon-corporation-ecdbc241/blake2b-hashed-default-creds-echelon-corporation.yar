rule blake2b_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a1="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
condition:
    ($a0 and $a1)
}
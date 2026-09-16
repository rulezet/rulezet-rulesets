rule nthash_hashed_default_creds_argus
{
    meta:
        id = "7RLxvtXxQn8b24vpHaL5OB"
        fingerprint = "1eb6ea6228efb9144a46525cd5dca46e6b8d66ceb2e4bb7744d7be4abb9fcf63"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcc7a35d120c4f1c5da1422a4201708"
    $a1="cf32420fd541befc7ac6bb7f2af8a741"
    $a2="e2136eefe3a79ac678a5e554bfbcdced"
    $a3="e2136eefe3a79ac678a5e554bfbcdced"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
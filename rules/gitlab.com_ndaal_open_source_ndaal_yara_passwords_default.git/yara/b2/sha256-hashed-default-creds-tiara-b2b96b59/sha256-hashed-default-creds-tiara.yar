rule sha256_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8581b8e80abe1d9d8417292f0772a6515618ada70b6c8b7be3a130f9b273b3d"
    $a1="51b57fa2315ff3308a2fa19b79c6682e7449ddc241eecc900180d064c16a24f0"
condition:
    ($a0 and $a1)
}
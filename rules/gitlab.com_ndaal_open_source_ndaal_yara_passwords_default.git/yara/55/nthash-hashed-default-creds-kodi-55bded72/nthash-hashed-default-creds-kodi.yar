rule nthash_hashed_default_creds_kodi
{
    meta:
        id = "3Zh7v4YncQeuopjqnUlV41"
        fingerprint = "98a86d0e6a9220e72d77c4b1d742538556fc452a68255d025af04d467e98f22d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86a57579725615cd87b45fe96394da9d"
    $a1="86a57579725615cd87b45fe96394da9d"
condition:
    ($a0 and $a1)
}
rule sha512_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1f889cb47eac435713ad436f4d32c9efa44b4c98ba3cc952bf7acc4a3bb9be3fce18a1a8a2d59d29899c96d6038b1e293c3153c65ab561e967b18049ab65b2b"
    $a1="e1f889cb47eac435713ad436f4d32c9efa44b4c98ba3cc952bf7acc4a3bb9be3fce18a1a8a2d59d29899c96d6038b1e293c3153c65ab561e967b18049ab65b2b"
condition:
    ($a0 and $a1)
}
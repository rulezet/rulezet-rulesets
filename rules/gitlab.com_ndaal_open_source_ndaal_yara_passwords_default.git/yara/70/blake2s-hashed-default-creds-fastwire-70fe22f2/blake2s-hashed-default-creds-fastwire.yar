rule blake2s_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="513dc4835af063d65b888b4af939a0fdf94f7908076b4cdaaffacee2c2e20abb"
    $a1="dcaac5c8574a8a788d94c5ae3246f63bab016598f6e75f09563f146e994bb668"
condition:
    ($a0 and $a1)
}
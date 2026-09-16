rule blake2s_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4757d31c39383a10c29ca84b4df9c9a3cacfec780bd1a52adc1619b97ddeb118"
    $a1="5bfd3bef7eb600a5ac9bd84c659ff3ab62e351360989d7929296c3e9caa5a911"
condition:
    ($a0 and $a1)
}
rule blake2b_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f015cca82b7e8dee81fe1e848143b8baf65cc78ba8cb987ceba93e261a5fd3b76ee12a9986e1420d1921813228ca465508c567714331312afe98600ecb2c35b3"
    $a1="09d2b5594542c7d070d694657395ca2536497d22dc0a31eac8b559e905f6129eb4b411fce2146c9ecb29005811b856075f80cacf13fbbf91db2e57265b290616"
condition:
    ($a0 and $a1)
}
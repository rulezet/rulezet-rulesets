rule blake2s_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14b9dbc85b0eab750605dac4f0149eab05003de7f39e61e7a95ab3f3bdcfa100"
    $a1="cd7aec459fb9c9fd67d89e6b733c394dd0503df3ab3d08e80894c9a4a14d086d"
condition:
    ($a0 and $a1)
}
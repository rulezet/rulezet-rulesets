rule blake2s_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7722ab1ca9ff316ecd58c7accf5697aae367c4da184c0f783fe215b278ee85d"
    $a1="c7722ab1ca9ff316ecd58c7accf5697aae367c4da184c0f783fe215b278ee85d"
condition:
    ($a0 and $a1)
}
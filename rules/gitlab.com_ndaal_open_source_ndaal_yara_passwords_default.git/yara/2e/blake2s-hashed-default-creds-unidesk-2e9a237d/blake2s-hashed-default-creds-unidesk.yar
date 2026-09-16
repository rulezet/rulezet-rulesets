rule blake2s_hashed_default_creds_unidesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unidesk."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98e6eb7841f31f985c47347ea7e88bcd0225131cdd992b1b7e71d0fb843d2dda"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
condition:
    ($a0 and $a1)
}
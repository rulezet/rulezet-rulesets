rule blake2s_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7773143d6f688b61884dd6709de4a4e3d8ec6968b15dfcefa11c3d4cef113d2a"
    $a1="01e9f1dd98151f82714350a2c4e5537b519e017cdb24b9d8ecf9c25d82b90792"
condition:
    ($a0 and $a1)
}
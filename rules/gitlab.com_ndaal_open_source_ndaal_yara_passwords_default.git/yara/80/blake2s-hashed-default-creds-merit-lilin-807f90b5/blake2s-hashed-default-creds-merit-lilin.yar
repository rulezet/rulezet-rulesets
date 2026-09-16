rule blake2s_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e4b7b7924b71970a31cf4b8837191e8aa42cefa2f77eea094695b4108c1af638"
    $a1="45fa58ff227a2f367e88041e855afa8ecfd56475f6b84b3c5e51592449c2aa9f"
condition:
    ($a0 and $a1)
}
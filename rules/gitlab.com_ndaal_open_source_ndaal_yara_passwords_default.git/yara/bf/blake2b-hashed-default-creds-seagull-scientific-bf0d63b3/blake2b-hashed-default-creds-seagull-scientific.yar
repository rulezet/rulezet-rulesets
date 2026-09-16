rule blake2b_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="c389a08ca48765ed7f0303e1823e4c20adf79b08368733b97fcb20b7c23d41e7487f826b4ee7c9c66b8e9d5ea50021271add19e347bfbfe0d5c6a053cf848589"
    $a2="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a3="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
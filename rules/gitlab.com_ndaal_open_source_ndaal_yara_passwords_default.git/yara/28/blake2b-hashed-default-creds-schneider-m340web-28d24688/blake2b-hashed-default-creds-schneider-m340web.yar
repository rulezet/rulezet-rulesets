rule blake2b_hashed_default_creds_schneider_m340web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
    $a1="ab1aaa9c1edaa8fa6a0798601d6b00ebf97a842abfdbc921ed8cc8b67f0af0cce5b46c4634c4a4b12c405e7580f028c90abf26db2f4d627e869d019330ab1534"
condition:
    ($a0 and $a1)
}
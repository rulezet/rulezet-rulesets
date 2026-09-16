rule blake2s_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1733a34cd0cd3b8ebf20e01eb3eb6dd480652c6ff9fff28f4179e8470fcb9079"
    $a1="ed1a92d93da90f5edb5e19f449e6661c0fc46b6a6fdb7cc86849f5400a827f3d"
condition:
    ($a0 and $a1)
}
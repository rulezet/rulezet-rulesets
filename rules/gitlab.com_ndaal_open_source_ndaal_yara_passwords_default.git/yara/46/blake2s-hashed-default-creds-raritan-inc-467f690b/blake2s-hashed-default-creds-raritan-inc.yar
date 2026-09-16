rule blake2s_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81f91510b3839c8485ec17d96c4ce9ea9a413bcce1aa40553d82b6cde7838b26"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="81f91510b3839c8485ec17d96c4ce9ea9a413bcce1aa40553d82b6cde7838b26"
    $a3="79555e7ca8c9f0ed3121c18141958523018e9a3515cf7d495c8527911e638eff"
    $a4="798109f4ea6168c47c6f1c57367b403356f64f4b10d13adf2f259f5d5b464957"
    $a5="f0640d2dcbf0ad5cb64e48724abb1c0d0ff2ce6a6bc767be8541257d71697663"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
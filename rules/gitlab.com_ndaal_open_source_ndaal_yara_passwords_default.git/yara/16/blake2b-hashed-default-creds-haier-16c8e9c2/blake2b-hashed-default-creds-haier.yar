rule blake2b_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5880c3f3e5faaf40a1c27b578d29f005643827ce8991fcab9021fee5e351e239d66b8c8261f2c81043a6ca374b7ae627e6fbf8014ca4eb9577931d28df907385"
    $a1="166469e6e9166d1506e50e6b92faa113f3cd59bf444151cc35f916e7016939a54dbb399f7aeb1127eba4ba043bedfceb01db0fb5041b84d7a8b57cd30a738d2f"
condition:
    ($a0 and $a1)
}
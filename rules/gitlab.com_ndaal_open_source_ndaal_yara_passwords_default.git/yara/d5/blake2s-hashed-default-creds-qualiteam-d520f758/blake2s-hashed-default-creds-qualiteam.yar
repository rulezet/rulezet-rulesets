rule blake2s_hashed_default_creds_qualiteam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for qualiteam."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
    $a1="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
condition:
    ($a0 and $a1)
}
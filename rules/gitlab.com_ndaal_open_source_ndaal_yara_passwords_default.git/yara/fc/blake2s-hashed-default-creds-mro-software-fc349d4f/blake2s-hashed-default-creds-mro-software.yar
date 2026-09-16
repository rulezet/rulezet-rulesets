rule blake2s_hashed_default_creds_mro_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mro_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a1="fe8c5a45db0ae3d73323ef3fabe0a7795fad29c243bc09576ecb4868d8cd623b"
condition:
    ($a0 and $a1)
}
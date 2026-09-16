rule blake2s_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
    $a1="6b98c00ae312dcb59af4d7769487889c3ab1a7366bdbf9dec1a1ed98d4ff8f1e"
condition:
    ($a0 and $a1)
}
rule sha256_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c04ef5da8feac07a4ce62109c0be500e357e732552a5d7a1049334c0fdda90e"
    $a1="115dc3606fbf8691fb69f2aefec86f2ecd302362a0502b3a9648bf2c4dc8290f"
condition:
    ($a0 and $a1)
}
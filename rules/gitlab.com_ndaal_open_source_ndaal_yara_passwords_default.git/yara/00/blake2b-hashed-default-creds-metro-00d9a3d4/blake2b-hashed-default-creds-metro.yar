rule blake2b_hashed_default_creds_metro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metro."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
    $a1="d6dc44ef4c274486bf10ad45b9b97537746443c665b875817010b6398aba76b321064857dd86568a6610e4de9ab520e57bbf64b11da6c1402873f4372d230414"
condition:
    ($a0 and $a1)
}
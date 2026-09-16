rule sha3_384_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1967cae834f6765af958ee9270e42c8adb97d49eb7896bece0b143313ddd0ea1e1e07f8b139166e32bc807e0f48c5ede"
    $a1="1967cae834f6765af958ee9270e42c8adb97d49eb7896bece0b143313ddd0ea1e1e07f8b139166e32bc807e0f48c5ede"
condition:
    ($a0 and $a1)
}
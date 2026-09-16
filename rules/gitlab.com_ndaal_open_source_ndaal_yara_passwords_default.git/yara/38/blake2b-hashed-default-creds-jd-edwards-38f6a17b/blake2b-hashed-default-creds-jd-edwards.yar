rule blake2b_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f765e0b2c9063d4360f60927cd783190c0aab36bfb8f4de60006860b1f52b64cb6d7b59bb7d96e2cbeafc86572e5b284cf43edf917fb97b6cee50c9bf4ef900"
    $a1="8f765e0b2c9063d4360f60927cd783190c0aab36bfb8f4de60006860b1f52b64cb6d7b59bb7d96e2cbeafc86572e5b284cf43edf917fb97b6cee50c9bf4ef900"
condition:
    ($a0 and $a1)
}
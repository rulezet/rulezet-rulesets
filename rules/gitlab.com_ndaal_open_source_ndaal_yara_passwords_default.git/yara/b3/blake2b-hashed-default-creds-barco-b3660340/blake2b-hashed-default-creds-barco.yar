rule blake2b_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc8fcf6757b0caa9ee0cbc5479e362cde34b48093c723014bfa93c30879f32c5cabda247d8b1bdf13897fd62d413d6f64c0367b9ab7997551a1ef66368e3b20"
    $a1="19918f956da358f894e24fefced570153b0be8dae0b7e189461852211dff503e0c77b7049bd48d1d30cd9702c21e5c496017acbb062edfd328f250ee05792ba0"
condition:
    ($a0 and $a1)
}
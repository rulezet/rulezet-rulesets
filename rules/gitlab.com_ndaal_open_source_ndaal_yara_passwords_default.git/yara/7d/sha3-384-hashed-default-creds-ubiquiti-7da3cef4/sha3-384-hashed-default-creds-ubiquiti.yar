rule sha3_384_hashed_default_creds_ubiquiti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
    $a1="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
condition:
    ($a0 and $a1)
}
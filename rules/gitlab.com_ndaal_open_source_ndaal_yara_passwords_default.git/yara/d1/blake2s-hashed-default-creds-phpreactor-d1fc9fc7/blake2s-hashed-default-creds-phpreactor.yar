rule blake2s_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="601c482cd4b2fb7b9b5646b9e0f007b28523b59d1bb569b270cc218f3daf8dcc"
    $a1="b4bfd4da344d6eaf12d3727c604aa5198977d089851e9700a148955e04dcee85"
condition:
    ($a0 and $a1)
}
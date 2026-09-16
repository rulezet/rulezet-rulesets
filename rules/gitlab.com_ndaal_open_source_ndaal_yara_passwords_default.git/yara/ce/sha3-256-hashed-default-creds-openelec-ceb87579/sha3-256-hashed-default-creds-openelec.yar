rule sha3_256_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18f960752cce9c8e492cd445a44e8ab5fe82f180790c17fc76437886d76ea081"
    $a1="423bf59865b7a81163719045708e050e7ab8d80222442c5af870786e1b7abe50"
condition:
    ($a0 and $a1)
}
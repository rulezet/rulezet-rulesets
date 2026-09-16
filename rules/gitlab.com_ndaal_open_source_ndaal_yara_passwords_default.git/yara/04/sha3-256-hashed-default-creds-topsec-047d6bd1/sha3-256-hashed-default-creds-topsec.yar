rule sha3_256_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6ea741e4dda4dbb7c51e643995afe2c08d6848e77f2d17db5fd8766b4d87387"
    $a1="880791b8f62367c22a2c09001f555136adb7e2d307649512f57d93cfb4e88607"
condition:
    ($a0 and $a1)
}
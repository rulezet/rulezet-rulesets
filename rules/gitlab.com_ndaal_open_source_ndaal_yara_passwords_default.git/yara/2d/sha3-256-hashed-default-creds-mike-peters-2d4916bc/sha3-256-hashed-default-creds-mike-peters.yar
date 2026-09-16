rule sha3_256_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9714558db29e3fcd29c75f873b615f093399010b9d3898f4264946ae8801ac93"
    $a1="b608192b14a7149c2466283c6a56b0029887698240ca43c8afcdf807942f4dd5"
condition:
    ($a0 and $a1)
}
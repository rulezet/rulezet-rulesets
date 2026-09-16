rule sha3_256_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
    $a1="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a2="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
    $a3="e3af3655adf7db74a945a34e361f8fa2ccd791da8e4727c5b853c81fdc33f483"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
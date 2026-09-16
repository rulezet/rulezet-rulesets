rule sha3_256_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="482af1dbde0c58dcc8a8712c34dbc85a39fb41dbff2cc237be518e2bc319f3bb"
    $a1="482af1dbde0c58dcc8a8712c34dbc85a39fb41dbff2cc237be518e2bc319f3bb"
condition:
    ($a0 and $a1)
}
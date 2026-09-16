rule sha3_384_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ce4c4f209549cbb92e1d7e83bbe808d7a638004243c95571f77df3fec91638d1b27408d4019a0c97699e38f73b0b13a"
    $a1="02ab0c08840ec2a13dc732ea81b0f0b8c8ca2fe02c3c0d3a81be2c6516a6dba5f086a5cbbb1031c0af2eb629fdb02130"
condition:
    ($a0 and $a1)
}
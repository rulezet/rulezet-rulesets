rule sha3_384_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa39f78ffe193ce57a4e25068aff4df9ab776c0a58f719aa39d9f0a2fa0a916cb2c0edb6e1767764972fac1bfaeb3815"
    $a1="aa39f78ffe193ce57a4e25068aff4df9ab776c0a58f719aa39d9f0a2fa0a916cb2c0edb6e1767764972fac1bfaeb3815"
condition:
    ($a0 and $a1)
}
rule sha3_256_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9b8ffc48ba0cbc8ba2f5025d44d4cf026b5e6d3150de6962c5aff59054b8124f"
    $a1="e92559e9a890b7ce627e2e92aa4438e8599a8ba46334ce0f08f67fab1e425163"
condition:
    ($a0 and $a1)
}
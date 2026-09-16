rule sha3_256_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bea26a68f1c3a2276e3e88002800cc5d269598edf4d618c89e3facedf6792158"
    $a1="8224866b82c8e5bd61873936dd988b02878f819d4d891a8b8325e5ee97940ece"
    $a2="a381c0e0dbbe117c6ae87d9ddebba0f126acd395cee9ad6e7e31f96920f1f458"
    $a3="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
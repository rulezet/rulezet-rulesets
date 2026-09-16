rule sha3_256_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18a921ceac023823379c712d7bc6077f3a8ec5e68b026170f6b6d6c44f2e494a"
    $a1="18a921ceac023823379c712d7bc6077f3a8ec5e68b026170f6b6d6c44f2e494a"
    $a2="bb883024addc15febe771f444d0b700bbca27b607c17fcef146d8212ad0c5e6d"
    $a3="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
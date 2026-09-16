rule sha3_224_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f41d2b09d14affafec1a0f46b4cc5f918a4fda59aa0284bd28abd70b"
    $a1="a8b9c397c6c27af802af87d16af4dbb5e8cbafe74e3f5a8fee8ed718"
condition:
    ($a0 and $a1)
}
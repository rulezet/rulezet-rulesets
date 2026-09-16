rule sha256_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a1="800250e0abe4745406b71b866e6d11f92a7dddfceaf305079bc8c9fbc8de4806"
condition:
    ($a0 and $a1)
}
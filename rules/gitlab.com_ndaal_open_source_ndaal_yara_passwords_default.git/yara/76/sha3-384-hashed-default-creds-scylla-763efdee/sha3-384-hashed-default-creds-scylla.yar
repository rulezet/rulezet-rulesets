rule sha3_384_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cbb41ff5703629f917e9ff62b7c3f058de68f79ebf16c52f3293d9b3e56a529af9910315b9557ca665d447616951048"
    $a1="6cbb41ff5703629f917e9ff62b7c3f058de68f79ebf16c52f3293d9b3e56a529af9910315b9557ca665d447616951048"
condition:
    ($a0 and $a1)
}
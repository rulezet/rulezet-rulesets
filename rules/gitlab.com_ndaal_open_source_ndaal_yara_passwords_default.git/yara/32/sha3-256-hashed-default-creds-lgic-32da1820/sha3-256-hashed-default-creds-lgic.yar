rule sha3_256_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d8de4a53ba7351cd6029e9aab427b36c1f72af123384912dd76802e7bd60b38"
    $a1="6d8de4a53ba7351cd6029e9aab427b36c1f72af123384912dd76802e7bd60b38"
condition:
    ($a0 and $a1)
}
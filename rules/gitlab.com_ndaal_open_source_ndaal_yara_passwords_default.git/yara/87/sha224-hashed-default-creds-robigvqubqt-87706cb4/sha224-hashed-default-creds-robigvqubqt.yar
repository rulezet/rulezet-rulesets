rule sha224_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a398030f8035b5f75aa7bf69abe3d39e4fef4c83890411d4389600f1"
    $a1="8e63db6c475a1854dac58408c2a9e938c9dab5e31a9775c2b5f35b8d"
condition:
    ($a0 and $a1)
}
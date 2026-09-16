rule sha3_256_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
    $a1="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
condition:
    ($a0 and $a1)
}
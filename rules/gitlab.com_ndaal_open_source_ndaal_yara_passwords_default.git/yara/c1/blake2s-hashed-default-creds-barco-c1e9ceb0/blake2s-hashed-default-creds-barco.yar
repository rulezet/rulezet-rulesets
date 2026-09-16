rule blake2s_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="256968d2ce18c311051107edb3f5a28ad1603d844ba99d2c90f7fb98e35da3f1"
    $a1="1e724e738142eb65f0b469601457c93477e81f3ce8dbb78bf0af059ce229aaea"
condition:
    ($a0 and $a1)
}
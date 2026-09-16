rule nthash_hashed_default_creds_lgic
{
    meta:
        id = "6fJdR8RblX0wYzsGq4aD2O"
        fingerprint = "8e3fd4d793b5383a6c3fcf8056ab66f23493cb03b0405e4a0f99028d9a10ed63"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad9a0f5dc77e451c5d78d9280dfa2886"
    $a1="ad9a0f5dc77e451c5d78d9280dfa2886"
condition:
    ($a0 and $a1)
}
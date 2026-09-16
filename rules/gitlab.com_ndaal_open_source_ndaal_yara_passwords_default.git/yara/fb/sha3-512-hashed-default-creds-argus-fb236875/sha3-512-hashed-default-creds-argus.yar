rule sha3_512_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bae826dd03f7c866258d7b93bde4be7ffe42d0039032436fa517abbe03da5babd149068e8a7f3f913a474a5c587ece5b7c005f7ad888b2c68e8651a7d40e518f"
    $a1="9e2ad5e823976faef863b663f7dd27f89cf92da0f6b809f0826bfaf0e797a6a6cad4e1829c29c57c4926a3aa7d41496d0a8e418f09727d104008d640edf35991"
    $a2="90a0022e1974ed15b6f901161c51e5f7452d66c428be5e6c49129c03c95969fc940f8cfc463fbb2e307f5e2c5b4aa01b1cafff01f64dd804b48c10b993a5f87c"
    $a3="90a0022e1974ed15b6f901161c51e5f7452d66c428be5e6c49129c03c95969fc940f8cfc463fbb2e307f5e2c5b4aa01b1cafff01f64dd804b48c10b993a5f87c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
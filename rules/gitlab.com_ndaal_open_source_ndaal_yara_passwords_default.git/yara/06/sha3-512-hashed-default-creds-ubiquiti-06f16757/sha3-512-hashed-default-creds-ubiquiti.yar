rule sha3_512_hashed_default_creds_ubiquiti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c60f2dea66779d66f9e7a7e1eb82421d95d95f7ef3f5e9ff50ae18206e219b6000c28a6fd55e76bb0373a417ab68cdfe9336996388c6ac6af413b70a68570e72"
    $a1="c60f2dea66779d66f9e7a7e1eb82421d95d95f7ef3f5e9ff50ae18206e219b6000c28a6fd55e76bb0373a417ab68cdfe9336996388c6ac6af413b70a68570e72"
condition:
    ($a0 and $a1)
}
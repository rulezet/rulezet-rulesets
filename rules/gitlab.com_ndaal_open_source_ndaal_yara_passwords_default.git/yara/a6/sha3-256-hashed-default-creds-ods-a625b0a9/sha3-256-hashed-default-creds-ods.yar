rule sha3_256_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9119c469783921fe3b564c0f3d4dd02e004d470e48a3b4bf3457fe2ec1ceaefe"
    $a1="9119c469783921fe3b564c0f3d4dd02e004d470e48a3b4bf3457fe2ec1ceaefe"
condition:
    ($a0 and $a1)
}
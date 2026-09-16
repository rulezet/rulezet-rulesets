rule sha3_256_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a06da966ec71d8a337a9ec0d9e8b5cda4a93583524d1a07ab959393712e3dce3"
    $a1="8fa9de94db19eb76b80daa866c54b3ac0221c54fd805dfd9f1bc2fd3e88d1a0d"
condition:
    ($a0 and $a1)
}
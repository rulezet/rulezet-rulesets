rule nthash_hashed_default_creds_155
{
    meta:
        id = "1NQWcEgxAiRBUPWGpVilIa"
        fingerprint = "1eaeed5c3ef4a826c7afd91c52b65f2c89ad18ba9cbdd3e8f6da0d60b08f397c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98ccaa746ecf56c4107e58674b04b1c2"
    $a1="d47ce0c3e3f78529db2f266d5e7afe8d"
    $a2="06da4042f45ed8e9a8d0574b0437c14b"
    $a3="06da4042f45ed8e9a8d0574b0437c14b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
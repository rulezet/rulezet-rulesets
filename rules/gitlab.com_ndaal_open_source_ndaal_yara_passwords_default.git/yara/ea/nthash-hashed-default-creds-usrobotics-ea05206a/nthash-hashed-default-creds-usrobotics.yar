rule nthash_hashed_default_creds_usrobotics
{
    meta:
        id = "5mZQBe5rW4150fJtYwq2CQ"
        fingerprint = "653249f0218350e8bb870c79391eb25ff9c0adbb22cd1ef3995166b77b007fec"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for usrobotics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="5d705a913bb120b86026c65c6a777da6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
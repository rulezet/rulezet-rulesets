rule nthash_hashed_default_creds_voiceobjects_germany
{
    meta:
        id = "lDW5htUm1fcvXJ4uRBMNt"
        fingerprint = "2c1df7bc439bc2a4d38efd2726f857d132bdaa52a54efdfef90c1395c300068b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voiceobjects_germany."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="d5498f703865504d6d443abe15f61e50"
condition:
    ($a0 and $a1)
}
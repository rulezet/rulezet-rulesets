rule sha3_224_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="cfbb56a314e406232e84144aa3b459691cc889b7b7d7406dcf2aeec1"
    $a2="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
    $a3="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
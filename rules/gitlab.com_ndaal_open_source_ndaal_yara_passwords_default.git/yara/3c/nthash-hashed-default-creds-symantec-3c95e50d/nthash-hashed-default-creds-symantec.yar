rule nthash_hashed_default_creds_symantec
{
    meta:
        id = "6rK4YbCOHcSLruRy0ovzeB"
        fingerprint = "89ff000357c65ca049285907fc0f2ecd48992fabf1658fa701019a29a28506a8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symantec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61cbf2b68fd8c843fc93511b9056890b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8ec898da77c4394d780bc73708f45250"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
rule nthash_hashed_default_creds_us_robotics
{
    meta:
        id = "36nK5fdHUgE2JLh0RvSurv"
        fingerprint = "fbd32f5f73245a62cabe4e32f4587e3285a3a5e9675e21b0cf1c7683acd738ad"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="1e1dd34b128de1968a44212e05d9e942"
    $a5="1e1dd34b128de1968a44212e05d9e942"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="7a21990fcd3d759941e45c490f143d5f"
    $a9="5d705a913bb120b86026c65c6a777da6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
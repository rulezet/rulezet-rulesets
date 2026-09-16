rule nthash_hashed_default_creds_kyocera
{
    meta:
        id = "43JHe3236EDYfd3hbPwAyG"
        fingerprint = "ae312dcdfb07d5d72b605a768bee07290416edc1fd0066387eab5e0e2f5a2531"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kyocera."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="4e47ea8491ff469fff2b6c65c945d59f"
    $a5="4e47ea8491ff469fff2b6c65c945d59f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
rule nthash_hashed_default_creds_ektron_inc
{
    meta:
        id = "6bIRTL5p0AfSvIBPxu5j8U"
        fingerprint = "63ae2e7186110a76dee05975b4b0590166ed7e26603ec47a428e4af3923344bd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="638b40ca41d1ebb2340af1fa3888a36d"
    $a1="638b40ca41d1ebb2340af1fa3888a36d"
    $a2="c2937b508a120f872ee6cfad1385c127"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
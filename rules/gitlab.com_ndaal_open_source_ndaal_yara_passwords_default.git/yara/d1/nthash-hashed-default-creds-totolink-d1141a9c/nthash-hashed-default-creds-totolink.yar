rule nthash_hashed_default_creds_totolink
{
    meta:
        id = "6XLaamu0IWWiRQMfyCYjfz"
        fingerprint = "8bf6992fd7a7f1f7822eef616fe32107777db077f36c1ea6a0a9d1038a181782"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for totolink."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="078468a45bb6141179e0ba08a78bac28"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
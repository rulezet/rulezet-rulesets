rule nthash_hashed_default_creds_bb_electronics
{
    meta:
        id = "H0Gpn4LCMlDsfnZp2AudD"
        fingerprint = "a610dafeabb82ba895f752aa3543fe877f4503cbaebcf9d62755b05f930a148c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bb_electronics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329153f560eb329c0e1deea55e88a1e9"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="a28100def40125ad83291bef0f1d6f7f"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
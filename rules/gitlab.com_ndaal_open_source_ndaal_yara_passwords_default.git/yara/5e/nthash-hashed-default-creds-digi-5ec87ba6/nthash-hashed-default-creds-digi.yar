rule nthash_hashed_default_creds_digi
{
    meta:
        id = "4PrdprNFf0TjJMZ6DHbizo"
        fingerprint = "8ea5597ae47c03e41f76ab5c82dacd42253d3be174f52cc2143fa9c73186d09a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a28100def40125ad83291bef0f1d6f7f"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="15078c69f48aa29c2ff5d6fdda2158ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
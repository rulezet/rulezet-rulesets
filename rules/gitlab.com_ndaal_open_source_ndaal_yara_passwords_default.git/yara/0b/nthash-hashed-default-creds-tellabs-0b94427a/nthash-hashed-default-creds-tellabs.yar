rule nthash_hashed_default_creds_tellabs
{
    meta:
        id = "7Hp8gkvPPxjgTgkPlGpBJD"
        fingerprint = "a956f1fa53b939a713fd2f1462934f3160f36c9319b344456c6243f076e320d8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="becd594cb71964ce2c46d5f149137fc9"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="bf26a6ea660879a2c7bdea7783401ae0"
    $a3="64bc276b2aee4976f68de3f83f86cd1a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
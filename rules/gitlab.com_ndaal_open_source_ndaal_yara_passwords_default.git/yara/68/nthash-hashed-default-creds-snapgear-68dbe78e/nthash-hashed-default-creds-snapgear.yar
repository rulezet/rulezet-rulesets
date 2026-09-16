rule nthash_hashed_default_creds_snapgear
{
    meta:
        id = "3EXr3GF76Xpfoor56lUyok"
        fingerprint = "6d48eea78376fbc65411da2ed71e93272b2d9b4c9ac0c9435d59eaab09ea789b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for snapgear."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ad0087f4086fc1771854c1a03e63ead"
    $a1="62eacbd980d31ba13d5a915755743d99"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="7d891ab402caf2e89ccdd33ed54333ac"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
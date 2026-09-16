rule nthash_hashed_default_creds_dlink_web
{
    meta:
        id = "3X1qfcieltl73fGCPhryer"
        fingerprint = "829b161105fbb2767ee8dcb27e6362ed71058ce34fc06697fefe6e2e375b9386"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dlink_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="7a21990fcd3d759941e45c490f143d5f"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="329153f560eb329c0e1deea55e88a1e9"
    $a7="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
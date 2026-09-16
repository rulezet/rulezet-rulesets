rule nthash_hashed_default_creds_sagem
{
    meta:
        id = "2Fl3GbmdX8TzRRVSARriAu"
        fingerprint = "d8f99b502d457a1ada53089be8df7b8bb69e1fc832038be4cb17777790cb64e3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sagem."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c130686c5e7390f6dfb455744d6ca639"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="ea484a5a2c81d8acfc3d098fae1eb343"
    $a5="ea484a5a2c81d8acfc3d098fae1eb343"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
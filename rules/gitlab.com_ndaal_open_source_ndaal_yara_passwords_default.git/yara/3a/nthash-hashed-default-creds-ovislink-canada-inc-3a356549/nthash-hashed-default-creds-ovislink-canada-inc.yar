rule nthash_hashed_default_creds_ovislink_canada_inc
{
    meta:
        id = "5x71Db8mP8LBHwKY2FuUrB"
        fingerprint = "86270de7820b3d610e10c0bf0e5cfcb6b2ca7e755b5f27f5814b37af94fbd2a1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ovislink_canada_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329153f560eb329c0e1deea55e88a1e9"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="57d583aa46d571502aad4bb7aea09c70"
    $a3="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
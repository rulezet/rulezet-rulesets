rule nthash_hashed_default_creds_mantis
{
    meta:
        id = "2kjMUllBvvqrifeXvsD7X3"
        fingerprint = "63b8da9e744133bf37ff57455677a8293484d673168e2b61a027d1f72acad7c7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mantis."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329153f560eb329c0e1deea55e88a1e9"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}
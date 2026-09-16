rule nthash_hashed_default_creds_blackbox
{
    meta:
        id = "4kGoGN6oKqV0ZBtRPgThWh"
        fingerprint = "b87336e8f630fae20d8aa2f52f2fd7a50b166232a655603b99e0d43eeab94b45"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blackbox."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db51013b2730e1f16df6db7c3a73ad60"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}
rule nthash_hashed_default_creds_control4
{
    meta:
        id = "1XjfV69nDMJjd2cW3KwdYH"
        fingerprint = "49d06513e44c734a03d632b5a6977da63700819bc1d5dae3fea853c6eae29cde"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for control4."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a8200c90b5b7eeaf2b170684dbc3540"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}
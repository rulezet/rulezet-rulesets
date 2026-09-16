rule nthash_hashed_default_creds_digicraft_software
{
    meta:
        id = "5Utroe81Vw1Kku685XzgI4"
        fingerprint = "c13c98a917fa4f96a8004404e3505d7ce94e4f76a3a0604c269bc91cd728d3ed"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7e86705ea4642f5b8a6e34d86333955"
    $a1="3c8411bf8b293d7f7d6aaafda3c46563"
condition:
    ($a0 and $a1)
}
rule nthash_hashed_default_creds_psion_teklogix
{
    meta:
        id = "1QbEDv1VpkIdqd3tJ5ctTL"
        fingerprint = "74fdf1e5c047bbf969f45107f45ac541e65d3c12cfd279c55605c1fbf471fc32"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ed11202d209f9d4bea955a3615225fc"
    $a1="1e1dd34b128de1968a44212e05d9e942"
condition:
    ($a0 and $a1)
}
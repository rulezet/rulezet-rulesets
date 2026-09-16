rule nthash_hashed_default_creds_solarwinds
{
    meta:
        id = "1UywMvYAJPnqQXofYFK9mJ"
        fingerprint = "5a1cea9464bc749249f7214f268865d2d3b1be8d17dfd37fb24847ef274e6eaa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0401f4b8d58a19e57f7c2af7d333804f"
    $a1="4dea917fd3de2e9692c8175036f9ec83"
    $a2="8e15ffa585780c791eae02c9767a4e4c"
    $a3="8e15ffa585780c791eae02c9767a4e4c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
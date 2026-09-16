rule nthash_hashed_default_creds_t_com
{
    meta:
        id = "nhA2gDqYAl4XZVwnSHZcl"
        fingerprint = "5a2021e9afbcc5f98a84609b004827c9b97bd0d9f5dea9a3ba3efc5bc1974491"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a1a58a99e7bf3ad22cff0ff981627f2"
    $a1="90ff121c8e498219861617c6bd7e6af4"
condition:
    ($a0 and $a1)
}
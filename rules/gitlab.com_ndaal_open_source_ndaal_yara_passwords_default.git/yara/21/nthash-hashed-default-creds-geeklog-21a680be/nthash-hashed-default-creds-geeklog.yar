rule nthash_hashed_default_creds_geeklog
{
    meta:
        id = "5VUkdFkjKJu1M5xIYGg6pP"
        fingerprint = "ccde304c0de6a7318f1bc23464e313424f2352c489d405372f051a3f949254e0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for geeklog."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="15078c69f48aa29c2ff5d6fdda2158ec"
condition:
    ($a0 and $a1)
}
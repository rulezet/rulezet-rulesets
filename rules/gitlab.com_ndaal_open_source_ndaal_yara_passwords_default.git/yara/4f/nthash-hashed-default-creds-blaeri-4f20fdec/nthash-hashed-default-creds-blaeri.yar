rule nthash_hashed_default_creds_blaeri
{
    meta:
        id = "5191HNJr1IpUw5wWOwBxN2"
        fingerprint = "0c092d9a83c07649da7d9838624b7bc907a6c2741f247acb32a52d0bccd22d5c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45c9eee8829ecdef5f70a26fa3b7b3fe"
    $a1="38011e141d4f40b592ed2ceefb01bd30"
condition:
    ($a0 and $a1)
}
rule nthash_hashed_default_creds_data_general
{
    meta:
        id = "1fvjnbRTvrkmwy7TYLVNPg"
        fingerprint = "7c7663f5f30fbb7b7d603afb974102d2412b30efd843bb20efa001aa67b4d6fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e337e31aa4c614b2895ad684a51156df"
    $a1="e337e31aa4c614b2895ad684a51156df"
    $a2="be4b40b070400db460bb0b2177515ab3"
    $a3="be4b40b070400db460bb0b2177515ab3"
    $a4="e337e31aa4c614b2895ad684a51156df"
    $a5="be4b40b070400db460bb0b2177515ab3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
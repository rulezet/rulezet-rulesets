rule nthash_hashed_default_creds_ge
{
    meta:
        id = "1nZKEgy4FkGBm5aV9IMHH3"
        fingerprint = "a3502ee99bca352cc36a5137e43c5537fe86659424873a159ccbb394e0bd7a6f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8474ed2bb7a35bd5135685838b87ea34"
    $a1="0f3c21d56b6c662ce8f4472d993a0c3d"
condition:
    ($a0 and $a1)
}
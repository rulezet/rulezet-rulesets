rule nthash_hashed_default_creds_mp3mystic
{
    meta:
        id = "3DOYzGpHmv8MCR6VNNXbLI"
        fingerprint = "9cbdd23898304eb7c833b90eed3d0eb8269191b3820a6cd0e81e8ad7277b517f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mp3mystic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da90e28cf764a557dcfdfb1a8b74df04"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}
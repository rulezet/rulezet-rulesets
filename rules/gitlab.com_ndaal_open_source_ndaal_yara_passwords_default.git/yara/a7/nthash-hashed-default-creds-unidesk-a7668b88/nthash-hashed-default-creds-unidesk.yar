rule nthash_hashed_default_creds_unidesk
{
    meta:
        id = "8L9Z8mZ7fbXCK0dY3kYuO"
        fingerprint = "f307c67e9b131ead6a2c77404157b901829a9c915dd8959c5c32066511b7fd9b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unidesk."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31a33c36d65413e2f4575410d906d9f9"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}
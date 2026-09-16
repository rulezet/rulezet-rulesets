rule nthash_hashed_default_creds_highpoint
{
    meta:
        id = "2SoZFbxAdRM92ELd7C4UvA"
        fingerprint = "de0b876ce268c671d688b281504bb78e55ee5c8623fe93a43a896ab0f0d26d76"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09ebbade67c22bfee34ebc87391b9fdb"
    $a1="797c35295ff162d2ea7ef1da95e3e4d7"
condition:
    ($a0 and $a1)
}
rule nthash_hashed_default_creds_bay_networks
{
    meta:
        id = "1B7H5Gi8HnGuXFtSYlbQiH"
        fingerprint = "589661c12278c5a3c1ed35b122919b7c60dae7e75e61c5aa1257cda69bca6cfb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5e9e0db50ba46b948853221be26da2b"
    $a1="d5e9e0db50ba46b948853221be26da2b"
condition:
    ($a0 and $a1)
}
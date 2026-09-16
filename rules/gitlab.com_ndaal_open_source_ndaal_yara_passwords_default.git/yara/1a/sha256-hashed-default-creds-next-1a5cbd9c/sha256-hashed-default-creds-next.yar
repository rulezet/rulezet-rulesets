rule sha256_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d648266682e89af95d2fd0f4e69e12818b89740e2c780eec89e44ae5892e5932"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
    $a3="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
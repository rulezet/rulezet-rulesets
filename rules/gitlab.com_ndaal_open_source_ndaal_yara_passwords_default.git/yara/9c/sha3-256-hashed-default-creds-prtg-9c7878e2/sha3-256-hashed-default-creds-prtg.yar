rule sha3_256_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7caf41ae779b5fc1e6457ea777e4845bfeb3b5098045bea509a9a86a3eab16d0"
    $a1="7caf41ae779b5fc1e6457ea777e4845bfeb3b5098045bea509a9a86a3eab16d0"
condition:
    ($a0 and $a1)
}
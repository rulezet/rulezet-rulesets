rule sha256_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a3="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
    $a4="8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf"
    $a5="571363723e1062b31f38a7f960c79d96d7a598586b71c58f9b7644a1bf578709"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
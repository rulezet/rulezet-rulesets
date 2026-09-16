rule sha256_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fbd3a8579c5b44363b2b7c122ec20a6c6f47fe1352efb498f4a8a6be2aced87"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ab38eadaeb746599f2c1ee90f8267f31f467347462764a24d71ac1843ee77fe3"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9"
    $a5="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
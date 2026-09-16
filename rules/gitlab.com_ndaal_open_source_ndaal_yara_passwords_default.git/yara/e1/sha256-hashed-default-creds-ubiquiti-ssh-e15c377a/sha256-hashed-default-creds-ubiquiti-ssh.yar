rule sha256_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
    $a5="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
rule sha256_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1f5175cac7219d5274210b1b36acd6e2693a84fe41be92d5810cca2dd7104ff"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
    $a3="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
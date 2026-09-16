rule sha256_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6529da56f1a1f6ae50652d544c131050256bc52568611b75049a90ca047bb221"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="06f25bcf0acf336cdee0f93659c7647d8ab7b9c3c7d1d6274887a8c1d1b758cb"
    $a3="4740ae6347b0172c01254ff55bae5aff5199f4446e7f6d643d40185b3f475145"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
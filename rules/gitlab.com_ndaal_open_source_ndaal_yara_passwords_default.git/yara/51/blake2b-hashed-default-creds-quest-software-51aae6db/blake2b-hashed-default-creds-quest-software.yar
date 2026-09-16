rule blake2b_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67a5184da943e9fdd7353f98655a5ec12a8c1ea14ddfe0ceb74c70b9b1e992812bdb329a9aafac6b26ccd269b75921a56b14160ccb374604dfab3a81c35e4c7c"
    $a1="67a5184da943e9fdd7353f98655a5ec12a8c1ea14ddfe0ceb74c70b9b1e992812bdb329a9aafac6b26ccd269b75921a56b14160ccb374604dfab3a81c35e4c7c"
condition:
    ($a0 and $a1)
}
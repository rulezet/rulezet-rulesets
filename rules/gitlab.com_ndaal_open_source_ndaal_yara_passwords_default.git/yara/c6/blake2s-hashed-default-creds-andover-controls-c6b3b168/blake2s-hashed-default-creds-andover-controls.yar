rule blake2s_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="723c2dd12aab4a510924e50f1ec63d4de287ca94798598d92dd88c649de3023d"
    $a1="723c2dd12aab4a510924e50f1ec63d4de287ca94798598d92dd88c649de3023d"
condition:
    ($a0 and $a1)
}
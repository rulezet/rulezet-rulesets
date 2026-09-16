rule nthash_hashed_default_creds_lindsay_electronics
{
    meta:
        id = "6xVltvgS5ykuWPV749KRzB"
        fingerprint = "6e822fbd849ff74c3d8e6ed2e456e7b52dbc6d352fed90df4aa0f84da7710a09"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8115c230e3b9c9203933917d770d4a51"
    $a1="98b724d9e8ea876a5c3133dd9df97a24"
    $a2="8115c230e3b9c9203933917d770d4a51"
    $a3="8115c230e3b9c9203933917d770d4a51"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
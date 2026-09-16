rule mysql323_hashed_default_creds_bb_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bb_electronics."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67457e226a1a15bd"
    $a1="67457e226a1a15bd"
    $a2="7273afe30183b483"
    $a3="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
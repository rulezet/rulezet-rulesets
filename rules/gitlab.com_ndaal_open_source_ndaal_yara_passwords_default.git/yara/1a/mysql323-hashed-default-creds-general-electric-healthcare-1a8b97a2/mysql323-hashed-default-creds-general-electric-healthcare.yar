rule mysql323_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="4077eb0b03ddce3b"
    $a2="6ae06afe6eea8d23"
    $a3="43e9a4ab75570f5b"
    $a4="6ae06afe6eea8d23"
    $a5="6ae06afe6eea8d23"
    $a6="7026502040899555"
    $a7="67457e226a1a15bd"
    $a8="6d45c652228f2d20"
    $a9="2c46fb58043ef1b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
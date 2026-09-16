rule mysql323_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6507a8e87071629c"
    $a1="60c033095644bd16"
    $a2="720e33351c7af4b4"
    $a3="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
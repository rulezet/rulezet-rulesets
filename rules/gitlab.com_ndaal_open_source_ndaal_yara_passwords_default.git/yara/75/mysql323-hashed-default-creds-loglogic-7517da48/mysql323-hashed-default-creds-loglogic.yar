rule mysql323_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="452574e9353ced92"
    $a1="67457e226a1a15bd"
    $a2="452574e9353ced92"
    $a3="3c8c1a8e271e4bad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
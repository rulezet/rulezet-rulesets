rule mysql323_hashed_default_creds_aztecj
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aztecj."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a8a8a22284b554e"
    $a1="7a8a8a22284b554e"
    $a2="43e9a4ab75570f5b"
    $a3="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
rule mysql323_hashed_default_creds_samsung
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="540054d93f8d665e"
    $a1="43e9a4ab75570f5b"
    $a2="2c20d5bd6ff371fc"
    $a3="2c20d5bd6ff371fc"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="2751330340a3093e"
    $a7="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
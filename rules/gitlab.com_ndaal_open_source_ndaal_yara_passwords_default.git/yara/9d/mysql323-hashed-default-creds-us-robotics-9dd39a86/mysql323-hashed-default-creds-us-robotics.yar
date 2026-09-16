rule mysql323_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e782c85379a326e"
    $a1="67457e226a1a15bd"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="441c54a74e618bc3"
    $a5="441c54a74e618bc3"
    $a6="43e9a4ab75570f5b"
    $a7="67457e226a1a15bd"
    $a8="2e782c85379a326e"
    $a9="734d18920be854d3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
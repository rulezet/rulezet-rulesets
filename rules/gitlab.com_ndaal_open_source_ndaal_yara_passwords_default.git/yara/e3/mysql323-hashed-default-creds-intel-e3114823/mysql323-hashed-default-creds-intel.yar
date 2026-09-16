rule mysql323_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d89770b0d299d60"
    $a1="3d89770b0d299d60"
    $a2="513370a2428dc17d"
    $a3="513370a2428dc17d"
    $a4="0c116ea61d0001b4"
    $a5="0c116ea61d0001b4"
    $a6="43e9a4ab75570f5b"
    $a7="67457e226a1a15bd"
    $a8="4690821c3b6058da"
    $a9="428aa52c3f8f41e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
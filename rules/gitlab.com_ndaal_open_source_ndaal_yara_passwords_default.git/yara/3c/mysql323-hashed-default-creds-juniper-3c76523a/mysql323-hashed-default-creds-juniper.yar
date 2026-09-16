rule mysql323_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="707ad979245de1d6"
    $a1="707ad979245de1d6"
    $a2="0696b6a17454d01e"
    $a3="0696b6a17454d01e"
    $a4="4b5698aa4603595b"
    $a5="43e9a4ab75570f5b"
    $a6="707ad979245de1d6"
    $a7="43e9a4ab75570f5b"
    $a8="55c1c81d14903932"
    $a9="43e9a4ab75570f5b"
    $a10="2f53d8097fac303a"
    $a11="2f53d8097fac303a"
    $a12="6d854ac121ebb529"
    $a13="60c033095644bd16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
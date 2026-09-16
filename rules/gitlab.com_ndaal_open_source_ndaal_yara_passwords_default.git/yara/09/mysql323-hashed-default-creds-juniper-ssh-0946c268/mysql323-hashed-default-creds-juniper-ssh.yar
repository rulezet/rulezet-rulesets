rule mysql323_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b5698aa4603595b"
    $a1="43e9a4ab75570f5b"
    $a2="707ad979245de1d6"
    $a3="43e9a4ab75570f5b"
    $a4="55c1c81d14903932"
    $a5="43e9a4ab75570f5b"
    $a6="707ad979245de1d6"
    $a7="707ad979245de1d6"
    $a8="2f53d8097fac303a"
    $a9="2f53d8097fac303a"
    $a10="0696b6a17454d01e"
    $a11="0696b6a17454d01e"
    $a12="6d854ac121ebb529"
    $a13="60c033095644bd16"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}
rule base64_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW4="
    $a1="YWRtaW4="
    $a2="YWRtaW4="
    $a3="dHJhY2VybGFi"
    $a4="dHJhY2VybGFi"
    $a5="dHJhY2VybGFi"
    $a6="cm9vdA=="
    $a7="I2JpZ2d1eQ=="
    $a8="Y3R1c2Vy"
    $a9="NCRhcHBz"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}
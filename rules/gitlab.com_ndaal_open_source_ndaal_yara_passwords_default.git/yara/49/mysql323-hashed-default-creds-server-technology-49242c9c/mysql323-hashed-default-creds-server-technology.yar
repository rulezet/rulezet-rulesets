rule mysql323_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d6e81067543ff55"
    $a1="0acf7a067baad695"
    $a2="5e16751127285799"
    $a3="3f4f8db1613d6799"
    $a4="5e16779627285a1e"
    $a5="3f4f8cb6613d669e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
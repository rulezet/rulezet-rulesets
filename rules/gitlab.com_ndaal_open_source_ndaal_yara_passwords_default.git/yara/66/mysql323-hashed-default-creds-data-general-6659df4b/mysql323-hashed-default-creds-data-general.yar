rule mysql323_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4297dfd67bfb01dd"
    $a1="4297dfd67bfb01dd"
    $a2="077f622149267fc3"
    $a3="077f622149267fc3"
    $a4="4297dfd67bfb01dd"
    $a5="077f622149267fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
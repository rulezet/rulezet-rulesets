rule mysql41_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B2D5231B669B19CEE9E7BBE5523F984549EDFE99"
    $a1="*B2D5231B669B19CEE9E7BBE5523F984549EDFE99"
    $a2="*244912A25B6B47FBD75733351AF26E4E69570424"
    $a3="*244912A25B6B47FBD75733351AF26E4E69570424"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
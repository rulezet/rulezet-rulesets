rule sha3_256_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afffd853f9c95caa3bd6db4c74bad7395ee52e5592f13fedab9c5b3ff59cef82"
    $a1="aeae63318b23cc3826a1b396f8ce6c5b83c89629acc8e5ed6ff944eb21d047ed"
    $a2="afffd853f9c95caa3bd6db4c74bad7395ee52e5592f13fedab9c5b3ff59cef82"
    $a3="38d0cf8a108289625fff55195a6bc3e822c6c7ef42a798e793de5a21de558fd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
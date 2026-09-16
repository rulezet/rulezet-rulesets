rule sha3_224_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f18c1b3d6556353ebccf1e5177d2e27850e33fd5a9d946b2caa36d3"
    $a1="8f18c1b3d6556353ebccf1e5177d2e27850e33fd5a9d946b2caa36d3"
    $a2="65fdede991ebecdd0b1dc7ebd9fe0314aaef26dcc5dd992b87560208"
    $a3="65fdede991ebecdd0b1dc7ebd9fe0314aaef26dcc5dd992b87560208"
    $a4="afb0ac8f76af5f0b4524aa517b4c76825927e4c0cc5f664522bc2c1c"
    $a5="afb0ac8f76af5f0b4524aa517b4c76825927e4c0cc5f664522bc2c1c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}
rule mysql323_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="58f7ee435f925abe"
    $a2="0c782be56afdcec9"
    $a3="5d8bbf5e2eeff98b"
    $a4="7a7eeba37575fe5e"
    $a5="7a7eeba37575fe5e"
    $a6="4297dfd67bfb01dd"
    $a7="4297dfd67bfb01dd"
    $a8="2c20d5bd6ff371fc"
    $a9="1a486e7929011a28"
    $a10="1a486e7929011a28"
    $a11="1a486e7929011a28"
    $a12="5336eb751494bdb1"
    $a13="67457e226a1a15bd"
    $a14="19b522a4743bf12c"
    $a15="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}
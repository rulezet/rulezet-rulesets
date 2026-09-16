rule mysql41_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FFCA13CB9665CB1C2EA4DBAC5F011440E84C7BCF"
    $a1="*FFCA13CB9665CB1C2EA4DBAC5F011440E84C7BCF"
    $a2="*CB99A0037F478625F065B90A709C9F253093157B"
    $a3="*CB99A0037F478625F065B90A709C9F253093157B"
    $a4="*6C72115F2701D784A331BD290370CED9697416A6"
    $a5="*B10C7E07BA3E1A37B2B8639F19064D2AFB52EF1A"
    $a6="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a7="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}
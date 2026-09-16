rule mysql41_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*02DCBB5647848698AF833D5CDD8E82358CF5119C"
    $a1="*02DCBB5647848698AF833D5CDD8E82358CF5119C"
    $a2="*689702948E6BFE035925935CDFFB1A19EF64265F"
    $a3="*689702948E6BFE035925935CDFFB1A19EF64265F"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
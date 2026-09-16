rule mysql41_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a1="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a2="*310AF8D67AE450FB86125F07FF75D1583528B45F"
    $a3="*25F807BD25B92C3093960A1B6DE8E95BAAEA53D4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
rule mysql41_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*75591BEA199F4B87A22B5ED7A4972DDAD059DDDE"
    $a1="*75591BEA199F4B87A22B5ED7A4972DDAD059DDDE"
    $a2="*59E5082E5C8A6E41D84407C596AE0AC2E21F1BFA"
    $a3="*8FE3F9FC6BECFCB7B0A52444E72F244C01337154"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
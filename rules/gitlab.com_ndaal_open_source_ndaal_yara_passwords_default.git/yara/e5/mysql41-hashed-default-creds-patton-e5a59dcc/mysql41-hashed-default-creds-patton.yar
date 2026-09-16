rule mysql41_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
    $a1="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
    $a2="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a3="*F5AB3475E4D0309381498567B7C7A270ADED2652"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}
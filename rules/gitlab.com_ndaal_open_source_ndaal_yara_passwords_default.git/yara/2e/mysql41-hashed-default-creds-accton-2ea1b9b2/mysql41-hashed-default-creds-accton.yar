rule mysql41_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a1="*7D2ABFF56C15D67445082FBB4ACD2DCD26C0ED57"
    $a2="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
    $a3="*1975D095AC033CAF4E1BF94F7202A9BBFEEB66F1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}